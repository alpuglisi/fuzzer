"""The site tree's data layer and API (CC-UI-0500, FR-UI-500..505).

Data-layer tests drive `fuzzlab.web.sitetree` over seeded stores shaped like what the
real writers produce (PA-0006): pipeline candidates (`audit/engine.py`, absolute evidence
URLs), crawl-imported endpoints/parameters (`tools/store_adapter.py`, including the raw
``?query`` a POST form action or captured request keeps), auditor candidates with and
without a parameter row, oracle findings (`oracle._write_finding`, ``finding_url``) and
target rows (`harness/pipeline.py`). API tests go through the app's routes.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import re
from pathlib import Path

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
    client = _client(seed.path)
    # Taken after the app starts: opening the store as the startup project records its
    # project row (FR-UI-455, project files). The claim here is that the routes write
    # nothing.
    before = _table_state(seed.path)
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


# --- code-review fixes (CC-UI-0503) ------------------------------------------------------

def test_reads_never_change_the_version_fingerprint(seed):
    """Code review A1: a reader opening the store creates an empty WAL, and closing the
    last connection removes it; neither is a data change."""
    rid = seed.run()
    seed.endpoint(rid, "/a")
    seed.close()
    v0 = st.store_version(seed.path)
    reader = Store(seed.path)
    reader.conn.execute("SELECT COUNT(*) FROM endpoint").fetchone()
    assert st.store_version(seed.path) == v0
    reader.close()
    assert st.store_version(seed.path) == v0
    seed.store = Store(seed.path)
    seed.conn = seed.store.conn


@pytest.mark.parametrize("params", [
    {"node": json.dumps({"o": "http://[::1"})},
    {"node": json.dumps({"o": "http://a＃b"})},
    {"node": '{"r":1,"s":["\\ud800"]}'},
    {"node": '{"r":1,"s":["a"],"m":"GET","p":"\\udfff"}'},
    {"node": json.dumps({"r": 1, "s": ["p"], "m": "GET", "p": "id", "l": None}),
     "after": f"{10 ** 30}:finding"},
])
def test_hostile_requests_are_400_not_500(mixed, params):
    seed, _a, _b = mixed
    client = _client(seed.path)
    assert client.get("/api/sitetree/children", params=params).status_code == 400
    if "after" not in params:
        assert client.get("/api/sitetree/node", params=params).status_code == 400


def test_an_out_of_range_before_is_400(mixed):
    seed, _a, _b = mixed
    client = _client(seed.path)
    r = client.get("/api/sitetree/node", params={"node": json.dumps({"o": ORIGIN}),
                                                  "before": 10 ** 30})
    assert r.status_code == 400


def test_a_malformed_stored_base_url_is_an_unreadable_origin_not_a_crash(seed):
    """BUG-0500: `canonical_origin` raises on a malformed authority; one such stored
    target row used to take every origin reader down (the tree, facets, ML holdout)."""
    from fuzzlab.core.runtarget import origin_of, run_origins
    bad = seed.run(base_url="http://[::1")
    good = seed.run()
    seed.endpoint(bad, "/b")
    seed.endpoint(good, "/g")
    assert origin_of("http://[::1") is None and origin_of(None) is None
    assert run_origins(seed.conn) == {bad: None, good: ORIGIN}
    labels_ = [h["label"] for h in kids(seed.conn)]
    assert labels_ == [ORIGIN, f"run #{bad} · auto — origin unreadable"]
    assert st.facets(seed.conn)["runs"][1]["host"].endswith("origin unreadable")
    holdout = pytest.importorskip("fuzzlab.ml.holdout")
    assert holdout._run_origins(seed.store) == {bad: None, good: ORIGIN}


def test_separator_characters_in_stored_strings_do_not_shift_fields(seed):
    """Code review A10/B4: target-supplied names may hold any character."""
    rid = seed.run()
    seed.cand(rid, "/p", "a\x1fb", location="body")
    seed.cand(rid, "/p", "\x00", location="query")
    ep = seed.endpoint(rid, "/q")
    pid = seed.param(rid, ep, "x\x1fy", "json")
    seed.raw_cand(rid, json.dumps({"category": "c"}), parameter_id=pid)
    got = labels(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}))
    assert got == ["\x00 · query", "a\x1fb · body"]
    assert labels(seed.conn, node({"o": ORIGIN, "s": ["q"], "m": "GET"})) == [
        "x\x1fy · json"]


def test_no_handler_in_sitetree_swallows_broadly():
    """PA-0106: every `except` in the site tree names its exceptions; none catches
    `Exception`/`BaseException` or is bare. Proven on a synthetic offender."""
    import ast
    from pathlib import Path

    def broad(source: str) -> list[int]:
        out = []
        for n in ast.walk(ast.parse(source)):
            if isinstance(n, ast.ExceptHandler):
                elts = [] if n.type is None else (
                    n.type.elts if isinstance(n.type, ast.Tuple) else [n.type])
                names = [e.id if isinstance(e, ast.Name) else
                         e.attr if isinstance(e, ast.Attribute) else "?" for e in elts]
                if not names or {"Exception", "BaseException"} & set(names):
                    out.append(n.lineno)
        return out
    assert broad("try:\n    f()\nexcept Exception:\n    pass\n"
                 "try:\n    f()\nexcept:\n    pass\n"
                 "try:\n    f()\nexcept (ValueError, builtins.BaseException):\n    pass\n"
                 "try:\n    f()\nexcept (ValueError, m.Gone):\n    pass\n") == [3, 7, 11]
    for mod in ("sitetree.py", "sitetree_routes.py"):
        src = (Path(st.__file__).parent / mod).read_text()
        assert broad(src) == [], mod


def test_endpoint_truncation_is_reported(seed, monkeypatch):
    rid = seed.run()
    for i in range(5):
        seed.finding(rid, "/p", f"x{i}")
    monkeypatch.setattr(st, "GROUP_CAP", 3)
    page = st.children(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}), st.Filters())
    assert page["truncated"] is True and len(page["children"]) == 3
    s = st.summary(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}), st.Filters())
    assert s["truncated"] is True
    monkeypatch.setattr(st, "GROUP_CAP", 0)            # nothing read: still said
    st.child_cache.clear()
    page = st.children(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}), st.Filters(),
                       version="v-zero")
    assert page == {"children": [], "next": None, "truncated": True}
    again = st.children(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}),
                        st.Filters(), version="v-zero")              # from the cache
    assert again["truncated"] is True


def test_the_child_list_cache_is_bounded(seed, monkeypatch):
    monkeypatch.setattr(st, "CACHE_ENTRIES", 2)
    monkeypatch.setattr(st, "CACHE_ENTRY_MAX", 3)
    monkeypatch.setattr(st, "CACHE_TOTAL_MAX", 4)
    cache = st._ChildCache()
    cache.put(("a", (), "v"), {"children": [{}] * 4, "truncated": False})  # over the bound
    assert cache.get(("a", (), "v")) is None
    cache.put(("b", (), "v"), {"children": [{}] * 2, "truncated": False})
    cache.put(("c", (), "v"), {"children": [{}] * 2, "truncated": False})
    cache.put(("d", (), "v"), {"children": [{}] * 1, "truncated": False})  # evicts b
    assert cache.get(("b", (), "v")) is None
    assert cache.get(("c", (), "v")) is not None and cache.get(("d", (), "v")) is not None
    assert cache._total <= 4 and len(cache._data) <= 2
    assert cache.get(("c", (), None)) is None           # never without a fingerprint


def test_the_projection_cache_is_bounded(seed, monkeypatch):
    monkeypatch.setattr(st, "PROJECTION_CACHE_MAX", 5)
    st._proj_cache.clear()
    rid = seed.run()
    for i in range(20):
        seed.cand(rid, f"/p{i}", "id")
    kids(seed.conn, node({"o": ORIGIN}))
    assert len(st._proj_cache) <= 5


def test_chunked_run_lists_match_json_each(mixed, monkeypatch):
    seed, _a, _b = mixed
    want = walk(seed.conn)
    st.child_cache.clear()
    monkeypatch.setitem(st._features, "json1", False)
    monkeypatch.setattr(st, "RUN_CHUNK", 1)
    assert walk(seed.conn) == want


def test_a_method_less_endpoint_groups_only_its_findings(seed):
    """Code review A7 (G8): other methods' rows resolve its findings' locations but are
    not listed under "(method not recorded)"."""
    rid = seed.run()
    seed.cand(rid, "/a.php", "id")
    seed.cand(rid, "/a.php", "id")
    f = seed.finding(rid, "/a.php", "id", method=None)
    eps = {e["label"]: e for e in kids(seed.conn, node({"o": ORIGIN, "s": ["a.php"]}))}
    nr = eps["(method not recorded) /a.php"]
    assert nr["rollup"]["candidates"] == 0 and nr["rollup"]["findings"] == 1
    (param,) = kids(seed.conn, node(nr["key"]))
    assert param["label"] == "id · query" and param["rollup"]["candidates"] == 0
    assert [i["id"] for i in kids(seed.conn, node(param["key"]))] == [f]
    s = st.summary(seed.conn, node(nr["key"]), st.Filters())
    assert s["rollup"]["candidates"] == 0 and s["rollup"]["findings"] == 1


def test_path_search_folds_ascii_only_everywhere(seed):
    """Code review A8: the roll-up (SQL) and the Issues list (Python) agree."""
    rid = seed.run()
    seed.finding(rid, "/Été", "id")
    seed.finding(rid, "/ABC", "id")
    host = node({"o": ORIGIN})
    for q, n in (("été", 0), ("Été", 1), ("abc", 1)):
        s = st.summary(seed.conn, host, st.parse_filters(q=q))
        assert s["rollup"]["findings"] == len(s["findings"]) == n, q


def test_an_endpoint_summary_counts_its_own_rows(seed):
    """Code review A13: the Contents pane of a selected endpoint shows its recorded
    endpoint and page rows and their last run."""
    rid = seed.run()
    seed.endpoint(rid, "/e.php")
    seed.page(rid, "/e.php")
    s = st.summary(seed.conn, node({"o": ORIGIN, "s": ["e.php"], "m": "GET"}), st.Filters())
    assert s["rollup"]["endpoints"] == 2 and s["rollup"]["last_run"] == rid


def test_evidence_urls_with_escaped_control_characters_pass_the_prefilter(seed):
    """Code review A9: `urlsplit` strips a tab from the path; the JSON keeps it."""
    rid = seed.run()
    seed.cand(rid, "/a\tb/c.php", "id")
    (child,) = kids(seed.conn, node({"o": ORIGIN}))
    assert child["label"] == "ab"
    assert labels(seed.conn, node(child["key"])) == ["c.php"]


def test_location_none_and_empty_are_separate_groups_on_every_page(seed):
    rid = seed.run()
    ep = seed.endpoint(rid, "/p")
    seed.param(rid, ep, "id", "")
    seed.finding(rid, "/p", "id", vuln_class="ssrf")        # no candidate: location null
    seed.cand(rid, "/p", "id", location="query")
    seed.cand(rid, "/p", "id", location="body")
    key = node({"o": ORIGIN, "s": ["p"], "m": "GET"})
    paged = [(c["param"], c["location"]) for c in kids(seed.conn, key, limit=1)]
    whole = [(c["param"], c["location"]) for c in st.children(
        seed.conn, key, st.Filters(), limit=50)["children"]]
    assert paged == whole and len(set(paged)) == len(paged) == 4


def test_planted_queries_on_finding_and_page_urls_never_show(seed):
    """Code review B7: `path_key` on every source, findings and pages included."""
    rid = seed.run()
    seed.page(rid, "/pg.php?tok=PQSECRET1")
    seed.finding(rid, "/f.php?tok=PQSECRET2", "id")
    text = json.dumps([c for _d, _l, c in walk(seed.conn)])
    text += json.dumps(st.summary(seed.conn, node({"o": ORIGIN}), st.Filters()))
    text += json.dumps(st.summary(seed.conn, node({"o": ORIGIN, "s": ["f.php"],
                                                   "m": "GET"}), st.Filters()))
    assert "PQSECRET" not in text and "/f.php" in text and "pg.php" in text


# --- known defects outside this lane, pinned (PA-0054(3)) ------------------------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="ML lane follow-up: ml/dataset.endpoint_key uses "
                   "to_path, dropping a fragment point's SPA route, while the oracle records "
                   "the finding at finding_url (/#/route); see CC-ML-0500")
def test_a_confirmed_dom_xss_finding_labels_its_fragment_candidate(seed):
    dataset = pytest.importorskip("fuzzlab.ml.dataset")
    rid = seed.run()
    seed.cand(rid, "/#/search", "q", category="xss", location="fragment")
    seed.finding(rid, "/#/search", "q", vuln_class="xss-dom")
    ds = dataset.build_dataset(seed.store, rid)
    assert list(ds.y) == [1]


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="UI follow-up: findingsview.derive_severity and "
                   "results.severity_of disagree (e.g. ssti: info vs critical); the site tree "
                   "uses the finding page's band (CC-UI-0500)")
def test_the_two_severity_bands_agree_for_every_oracle_class():
    from fuzzlab.oracle import strategies
    from fuzzlab.web.results import severity_of
    classes = {c.vuln_class for _n, c in inspect.getmembers(strategies, inspect.isclass)
               if isinstance(getattr(c, "vuln_class", None), str) and c.vuln_class}
    assert {vc: derive_severity(vc) for vc in classes} == {
        vc: severity_of(vc) for vc in classes}


def test_a_lone_surrogate_in_stored_evidence_is_unreadable_not_a_500(seed):
    """Code review re-check (A-N2, B-N1; PA-0500(2)): JSON may escape a lone surrogate,
    which SQLite cannot hold; the row is unreadable and counted, the tree still loads."""
    rid = seed.run()
    seed.cand(rid, "/ok.php", "id")
    seed.raw_cand(rid, '{"rule_id":"R","category":"xss","url":"http://h/a\\ud800b",'
                       '"param":"q","method":"GET","location":"query"}')
    seed.raw_cand(rid, '{"rule_id":"R","category":"xss","url":"http://h/p",'
                       '"param":"a\\udfff","method":"GET","location":"query"}')
    (host,) = kids(seed.conn)
    assert host["rollup"]["problems"]["unreadable"] == 2
    assert labels(seed.conn, node(host["key"])) == ["ok.php"]
    client = _client(seed.path)
    assert client.get("/api/sitetree/node", params={"node": host["key"]}).status_code == 200


# --- the store version (CC-UI-0068, FR-UI-505, BUG-0534; DRAFT-AU-SITETREE rev 2) -------
# Every writer below runs in ANOTHER PROCESS (`tests/_xproc.py`, D4): the web server is one
# process and a scan another, and SQLite's locks, shared memory and WAL fold are per
# process. The web process's own readers are this process's connections.

def _fresh_store(tmp_path, name="v.db"):
    path = tmp_path / name
    with Store(path) as s:
        s.start_run("t", "h")
    return path


def test_a_readers_last_close_never_changes_the_version(tmp_path):
    """E1 (M1 case 1): a writer in another process commits while a web reader is open,
    so its close leaves the frames in the WAL; the reader's later close was the last and
    folded the WAL, which changed the version with no write."""
    from fuzzlab.web.projects import open_reader
    from tests._xproc import Writer
    path = _fresh_store(tmp_path)
    reader = open_reader(str(path))
    reader.conn.execute("SELECT count(*) FROM run").fetchone()
    with Writer(path) as w:
        w("open")
        w("ins", 3)
        w("close")
    v = st.store_version(path)
    reader.close()
    assert st.store_version(path) == v


def test_every_commit_of_a_held_writer_in_another_process_changes_the_version(tmp_path):
    """E2 (M1 case 5, M4): after a WAL restart a commit lands inside the WAL's old extent
    and the old fingerprint missed it (2782 of 3000). Asserts a restart happened, so the
    case is not vacuous."""
    from tests._xproc import Writer
    path = _fresh_store(tmp_path)
    with Writer(path) as w:
        w("open")
        prev, unseen = st.store_version(path), 0
        for _ in range(3000):
            w("ins", 1, 400)
            cur = st.store_version(path)
            unseen += cur == prev
            prev = cur
        restarts = w("wal_header")["checkpoint_seq"]
        w("close")
    assert restarts > 0, "no WAL restart happened: the case would prove nothing"
    assert unseen == 0


def _web_reader_cycle(path, _w):
    from fuzzlab.web.projects import open_reader
    r = open_reader(str(path))
    try:
        r.conn.execute("SELECT count(*) FROM endpoint").fetchone()
    finally:
        r.close()


_NO_WRITE = {
    "a web reader opens, reads and closes": _web_reader_cycle,
    "the writer process closes with frames in the WAL": lambda path, w: w("close"),
    "a passive checkpoint by the writer process": lambda path, w: w("checkpoint", "PASSIVE"),
    "an empty write transaction": lambda path, w: w("empty"),
    "an UPDATE that matches no row":
        lambda path, w: w("sql", "UPDATE endpoint SET method=method WHERE 0"),
}


@pytest.mark.parametrize("case", sorted(_NO_WRITE))
def test_no_read_close_or_checkpoint_changes_the_version(tmp_path, case):
    """E1 (M1 cases 2 and 3; M2 C1-C5): nothing that leaves the content as it was
    changes the version."""
    from tests._xproc import Writer
    path = _fresh_store(tmp_path)
    with Writer(path) as w:
        w("open")
        w("ins", 5)                                  # frames in the WAL, the writer open
        v = st.store_version(path)
        _NO_WRITE[case](path, w)
        assert st.store_version(path) == v
        if "closes with frames" not in case:
            w("close")


def test_a_commit_hidden_by_a_wal_restart_is_never_served_from_the_cache(tmp_path):
    """E2 through the route (G11): a child list cached after a WAL restart was served
    again for a commit that kept the WAL's size and header."""
    from tests._xproc import Writer
    path = tmp_path / "c.db"
    with Store(path) as s:
        rid = s.start_run("auto", "h")
        s.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (rid, ORIGIN))
        s.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, '/a', 'GET')",
                       (rid,))
        s.conn.commit()
    st.child_cache.clear()
    client = _client(path)
    (host,) = [c["key"] for c in client.get("/api/sitetree/children").json()["children"]
               if c["label"] == ORIGIN]

    def shown():
        return [c["label"] for c in client.get(
            "/api/sitetree/children", params={"node": host}).json()["children"]]
    with Writer(path) as w:
        w("open")
        w("ins", 1500, 400)                          # a scan: the WAL grows past 1000 pages
        w("checkpoint", "PASSIVE")
        w("ins", 1, 400)                             # the WAL restarts at its start
        assert shown() == ["a"]                      # cached under this version
        w("sql", "INSERT INTO endpoint (run_id, url, method) VALUES (?, '/b', 'GET')", rid)
        assert shown() == ["a", "b"]
        w("close")


def test_a_replaced_or_removed_store_changes_the_version(tmp_path):
    """Fact F: a store replaced at its path (a new inode) is another store; a removed one
    has no version, and asking recreates nothing."""
    path = _fresh_store(tmp_path, "a.db")
    v = st.store_version(path)
    other = _fresh_store(tmp_path, "b.db")
    os.replace(other, path)
    after = [st.store_version(path), st.store_version(path)]
    assert v not in after and after[-1] is not None
    os.unlink(path)
    assert st.store_version(path) is None
    assert [s for s in ("", "-wal", "-shm", "-journal")
            if os.path.exists(str(path) + s)] == []


def test_rollback_journal_commits_are_seen_under_a_coarse_clock(tmp_path):
    """FR-UI-505's old residual, emulated: a same-size UPDATE inside one mtime tick
    (`os.utime` restores the mtime; this host's clock is fine-grained, M6)."""
    import sqlite3
    path = tmp_path / "r.db"
    plain = sqlite3.connect(path)
    plain.execute("PRAGMA journal_mode=DELETE")
    plain.execute("CREATE TABLE t (v INTEGER)")
    plain.execute("INSERT INTO t VALUES (0)")
    plain.commit()
    unseen = 0
    try:
        for i in range(1, 21):
            before = os.stat(path)
            v = st.store_version(path)
            plain.execute("UPDATE t SET v=?", (i % 2,))
            plain.commit()
            assert os.stat(path).st_size == before.st_size
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            unseen += st.store_version(path) == v
    finally:
        plain.close()
    assert unseen == 0


def test_the_store_version_never_creates_or_migrates_a_store(tmp_path):
    """NFR-UI-read-only: asking for a version creates nothing, and an older-schema
    store is never migrated nor switched to WAL by it."""
    import sqlite3
    missing = tmp_path / "missing.db"
    assert st.store_version(missing) is None
    assert [s for s in ("", "-wal", "-shm", "-journal")
            if os.path.exists(str(missing) + s)] == []
    old = tmp_path / "old.db"
    plain = sqlite3.connect(old)
    plain.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    plain.execute("INSERT INTO schema_version VALUES (1)")
    plain.commit()
    plain.close()
    assert st.store_version(old) is not None
    plain = sqlite3.connect(old)
    try:
        assert plain.execute("SELECT version FROM schema_version").fetchall() == [(1,)]
        assert plain.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        plain.close()


def test_the_project_listing_never_serves_a_summary_older_than_its_bound(tmp_path,
                                                                          monkeypatch):
    """`core.project._stat_key` (the Projects listing's cache) missed a commit inside the
    WAL's old extent within one coarse mtime tick, for ever. Fixed in CC-CORE-0071 by a
    bound on a cached summary's age (`_summary_clock`); emulated with `os.utime`."""
    from fuzzlab.core import project as core_project
    from tests._xproc import Writer
    now = [1000.0]
    monkeypatch.setattr(core_project, "_summary_clock", lambda: now[0], raising=False)
    path = _fresh_store(tmp_path, "l.fuzzlab")
    with Writer(path) as w:
        w("open")
        w("ins", 1500, 400)
        w("checkpoint", "PASSIVE")
        w("ins", 1, 400)                             # the WAL restarts
        core_project._SUMMARY_CACHE.clear()
        main, wal = os.stat(path), os.stat(str(path) + "-wal")
        runs = core_project.summary(path)["runs"]
        w("sql", "INSERT INTO run (tool, config_hash) VALUES ('late', 'h')")
        assert os.stat(str(path) + "-wal").st_size == wal.st_size     # inside the old extent
        os.utime(path, ns=(main.st_atime_ns, main.st_mtime_ns))       # one coarse tick
        os.utime(str(path) + "-wal", ns=(wal.st_atime_ns, wal.st_mtime_ns))
        now[0] += 3600.0                                              # an hour later
        assert core_project.summary(path)["runs"] == runs + 1
        w("close")


_CHANGE_ATTRS = {"st_size", "st_mtime", "st_mtime_ns", "st_ctime", "st_ctime_ns"}
_CHANGE_CALLS = {"getsize", "getmtime", "getctime", "read"}


def store_fingerprints(src: str) -> list[str]:
    """Functions that combine a ``-wal`` name with its size, a time or a raw read: a
    change signal inferred from SQLite's storage side effects (PA-0534(1))."""
    out: list[str] = []

    def visit(node, where):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, ast.ClassDef):
                visit(ch, f"{where}.{ch.name}" if where else ch.name)
            elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{where}.{ch.name}" if where else ch.name
                docs = {id(s.value) for s in ast.walk(ch)
                        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)}
                wal = change = False
                for n in ast.walk(ch):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) \
                            and "-wal" in n.value and id(n) not in docs:
                        wal = True
                    if isinstance(n, ast.Attribute) and n.attr in _CHANGE_ATTRS:
                        change = True
                    if isinstance(n, ast.Call):
                        f = n.func
                        nm = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                        change = change or nm in _CHANGE_CALLS
                if wal and change:
                    out.append(name)
                visit(ch, name)
            else:
                visit(ch, where)

    visit(ast.parse(src), "")
    return out


#: The reasoned allowances: none is a "has the store changed" signal a page relies on.
_FINGERPRINT_ALLOWED = {
    "fuzzlab/core/project.py::_stat_key": "the Projects listing's cache key; a summary is "
        "never served older than its bound (`_summary_clock`), so a missed coarse tick "
        "costs at most that bound",
    "fuzzlab/core/project.py::file_facts": "a display of size and last write, not a "
        "change signal",
    "fuzzlab/core/project.py::copy_to": "a disk-space estimate before a copy",
}


def test_no_module_fingerprints_the_store_from_its_files():
    """PA-0534(1): the store version is SQLite's own change counter (SP-58); nothing
    infers a store change from the WAL's size, times or header -- the owner included."""
    found = []
    for path in sorted((Path(__file__).resolve().parents[1] / "fuzzlab").rglob("*.py")):
        rel = path.relative_to(Path(__file__).resolve().parents[1]).as_posix()
        found += [f"{rel}::{f}" for f in store_fingerprints(path.read_text("utf-8"))]
    assert sorted(set(found) - set(_FINGERPRINT_ALLOWED)) == []
    assert sorted(set(_FINGERPRINT_ALLOWED) - set(found)) == []        # no stale allowance


def test_the_store_fingerprint_guard_catches_synthetic_offenders():
    """PA-0034(2): the 7ebf48a body, a `Path.stat()` variant and an `os.path.getmtime`
    variant are found; identity checks and docstrings are not."""
    old = ('def store_version(path):\n'
           '    st = os.stat(path)\n'
           '    with open(path + "-wal", "rb") as fh:\n'
           '        header = fh.read(32)\n'
           '        size = os.fstat(fh.fileno()).st_size\n')
    pathstat = ('def v(p):\n    return Path(str(p) + "-wal").stat().st_mtime_ns\n')
    getm = ('def v(p):\n    return os.path.getmtime(f"{p}-wal")\n')
    near = ('def ident(p):\n    """The -wal\'s size is not read here."""\n'
            '    st = os.stat(str(p) + "-wal")\n    return (st.st_dev, st.st_ino)\n'
            'def gone(p):\n    return os.path.lexists(str(p) + "-wal")\n')
    assert store_fingerprints(old) == ["store_version"]
    assert store_fingerprints(pathstat) == ["v"]
    assert store_fingerprints(getm) == ["v"]
    assert store_fingerprints(near) == []
