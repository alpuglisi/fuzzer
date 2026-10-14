"""Forms phase 5: SPA route query-parameter discovery (FR-CRAWL-17, CC-CRAWL-0027).

Juice Shop's ``#/track-result?id=`` renders the order id the server echoes as trusted
HTML, but the crawler only ever visited bare routes (``scan_routes`` yields
``#/track-result``), so no fragment point existed and M6 never ran there. Now:

* **Q1/Q2, the scan** (`spa.scan_query_params`, in the one `spa.scan_script` call):
  paired (route, names) from ``navigate([..],{queryParams:{..}})``, Vue ``push`` and
  React literals; unpaired names from ``queryParams.x`` and friends; linear, bounded,
  sensitive names dropped;
* **Q3, seeds**: each pair becomes one crawl URL with the filler (``/`` for a
  redirect-ish name), through the route, destructive and window gates;
* **Q4**: every seed and probe load runs inside the reveal window (no write, no
  navigation, no WebSocket message), which then leaves the page for ``about:blank``;
* **Q5, the observation probe**: unpaired names are attached to a route only when this
  load's fresh, word-shaped marker is seen in the DOM or the load's own requests -- a
  probe load records nothing;
* **Q6/Q7**: seeds become fragment points (and a GET XHR's query a query point); counts.

Real-browser tests run Chromium against loopback fakes (``tests/_spa_query_fixture.py``)
and fail rather than skip under ``FUZZLAB_REQUIRE_BROWSER=1``.
"""

from __future__ import annotations

import contextlib
import random
import string
import time

import pytest

from fuzzlab.core.redaction import looks_like_identifier
from fuzzlab.tools import spa
from tests._spa_fixture import Recorder, chromium_or_skip, db_rows, db_text, run_crawl
from tests._spa_query_fixture import QuerySpa, TrackSpa


def _scan(text):
    q = spa.scan_query_params(text)
    return q.pairs, q.unpaired, q.refused


# =====================================================================================
# Q1/Q2: the scan
# =====================================================================================
#: A synthetic excerpt shaped like Juice Shop's main.js (minified, backtick literals).
JUICE_SHAPED = (
    "search(t){if(t){let i={queryParams:{q:t}};this.ngZone.run(()=>L$1(this,null,"
    "function*(){return yield this.router.navigate([`/search`],i)}))}}"
    "this.router.navigate([`403`],{skipLocationChange:!0,queryParams:{error:t}})}"
    "return yield this.router.navigate([`/login`],{queryParams:{redirectUrl:`/basket`}})"
    "return yield this.router.navigate([`/track-result`],{queryParams:{id:t}})}))}"
    "this.router.navigate([`/chatbot/conversation`,i],{queryParams:{initialMessage:t}})}"
    "this.router.navigate([],{queryParams:Zc(t)})}"
    "this.router.navigate([],{relativeTo:this.route,queryParams:{},replaceUrl:!0})"
    "ngOnInit(){this.orderId=this.route.snapshot.queryParams.id,"
    "let i=this.route.queryParams.subscribe(n=>{this.f=n});"
    "let p=this.route.snapshot.queryParams.challenge;"
    "n=this.route.snapshot.queryParamMap.get(`redirectUrl`)??`/search`;"
    "this.router.navigate([`/payment`,`shop`])")


def test_angular_pairs_and_unpaired_reads_from_a_juice_shop_shaped_bundle():
    pairs, unpaired, refused = _scan(JUICE_SHAPED)
    assert pairs == {"403": ["error"], "login": ["redirectUrl"], "track-result": ["id"]}
    # the standalone queryParams object (passed to navigate as a variable) is unpaired
    assert unpaired == ["q", "id", "challenge", "redirectUrl"]
    assert refused == {spa.Q_DYNAMIC: 1, spa.Q_NONLITERAL: 1}


def test_vue_push_and_react_literals():
    pairs, unpaired, _r = _scan(
        "this.$router.push({path:'/search',query:{q:e,page:2}});"
        "r.replace({name:'x',query:{tab:1}});"
        "navigate('/items?cat=1&sort=asc');"
        "'<Link to=\"/prod?pid=3\">';"
        "e(Link,{to:\"/l?lk=1\"});"
        "this.$route.query.sort; route.query.filter; myroute.query.nope;"
        "u.searchParams.get(\"page2\"); new URLSearchParams(location.search).get('ref');"
        "queryParams['tab2']")
    assert pairs == {"/search": ["q", "page"], "/items": ["cat", "sort"],
                     "/prod": ["pid"], "/l": ["lk"]}
    assert unpaired == ["tab", "sort", "filter", "page2", "ref", "tab2"]


@pytest.mark.parametrize("body", [
    "navigate([`/r${x}`],{queryParams:{a:1}})",           # a template substitution
    "navigate([`/r`,id],{queryParams:{a:1}})",             # a dynamic segment
    "navigate(['/r'],{queryParams:makeQuery(a)})",         # a non-literal query
    "navigate(['/r'],{queryParams:{}})",                   # nothing
    "navigate(['/r'],opts)",                               # options not literal
    "query:{a:1}",                                          # Vue query outside push
    "x.get('a'); get(`b`); query.c",                       # never a bare get( / query
    "navigate(['/r'],{queryParams:{'a-b':1,'1x':2}})",     # not identifier-shaped
])
def test_near_misses_give_no_pair(body):
    assert spa.scan_query_params(body).pairs == {}


def test_a_dynamic_segment_is_refused_and_the_bare_first_element_never_seeded():
    """B7: ``navigate([`/chat`, id], {queryParams: {..}})`` names a parameterised route;
    its names are not paired with ``/chat`` and are not offered as unpaired."""
    pairs, unpaired, refused = _scan(
        "navigate([`/chatbot/conversation`,i],{queryParams:{initialMessage:t}})")
    assert pairs == {} and unpaired == [] and refused == {spa.Q_DYNAMIC: 1}


@pytest.mark.parametrize("body", [
    "navigate([base,`/x`],{queryParams:{a:1}})",          # a non-literal first element
    "navigate([`/x`,`y`,i],{queryParams:{a:1}})",
])
def test_any_non_literal_element_of_a_multi_element_route_is_a_dynamic_segment(body):
    assert _scan(body) == ({}, [], {spa.Q_DYNAMIC: 1})


def test_an_empty_or_lone_non_literal_route_leaves_its_names_unpaired():
    assert _scan("navigate([],{queryParams:{a:1}});navigate([r],{queryParams:{b:1}})") \
        == ({}, ["a", "b"], {})


def test_a_route_array_of_literals_is_joined():
    assert _scan("navigate([`/payment`,`shop`],{queryParams:{mode:x}})")[0] == {
        "payment/shop": ["mode"]}


def test_an_earlier_navigation_never_takes_a_later_ones_query():
    """A-M4: ``navigate([/a]);…navigate([/b],{queryParams:{x}})`` -> /b:x only."""
    pairs, unpaired, _r = _scan(
        "this.router.navigate([`/a`]);foo(1,2);this.router.navigate([`/b`],"
        "{queryParams:{x:1}})")
    assert pairs == {"b": ["x"]} and unpaired == []


def test_members_and_calls_are_never_names():
    pairs, unpaired, _r = _scan(
        "r.queryParams.subscribe(f); r.queryParams.pipe(m); r.queryParams.keys;"
        "r.queryParams.forEach; r.queryParams.has; r.queryParams.getAll; r.queryParams.get;"
        "r.queryParams.toString; r.queryParams.custom(1); r.queryParams.ok;"
        "navigate(['/m'],{queryParams:{f(){return 1},...rest,[k]:v,g:1}})")
    assert unpaired == ["ok"] and pairs == {"m": ["g"]}


def test_sensitive_names_are_dropped_and_counted_by_class_only():
    pairs, unpaired, refused = _scan(
        "navigate(['/x'],{queryParams:{token:t,password:p,securityAnswer:a,q:1}});"
        "r.queryParams.api_key; r.queryParamMap.get('sessionId'); r.queryParams.page")
    assert pairs == {"x": ["q"]} and unpaired == ["page"]
    assert refused == {spa.Q_SENSITIVE: 5}


def test_names_and_anchors_are_capped():
    many = "".join(f"r.queryParams.n{i};" for i in range(spa.MAX_QUERY_NAMES + 7))
    q = spa.scan_query_params(many)
    assert len(q.unpaired) == spa.MAX_QUERY_NAMES
    assert q.refused == {spa.Q_NAME_CAP: 7}
    noise = "x.queryParams.get(1);" * (spa.MAX_QUERY_ANCHORS + 10) + "r.queryParams.late;"
    q = spa.scan_query_params(noise)
    assert q.anchor_cap and q.anchors == spa.MAX_QUERY_ANCHORS and q.unpaired == []


def test_the_window_is_bounded_no_pair_across_500kb():
    body = "navigate([`/a`]," + " " * (500 * 1024) + "{queryParams:{x:1}})"
    assert spa.scan_query_params(body).pairs == {}
    assert spa.scan_query_params(body.replace(" " * (500 * 1024), " ")).pairs == {
        "a": ["x"]}


def test_scan_script_is_one_call_with_one_size_cap():
    body = "{path:'track'};navigate([`/track`],{queryParams:{id:t}})"
    routes, query = spa.scan_script(body)
    assert routes == ["track"] and query.pairs == {"track": ["id"]}
    assert spa.scan_script(body + " " * spa.MAX_SCRIPT_BYTES) is None
    assert spa.scan_query_params(body + " " * spa.MAX_SCRIPT_BYTES) is None


def _near_misses(size: int) -> dict:
    """4 MB adversarial bodies: every anchor repeated as a near miss."""
    return {
        "navigate run": "navigate([`" * (size // 11),
        "unclosed options": "navigate([`/a`],{queryParams:{x" * (size // 32),
        "queryParams object run": "queryParams:{" * (size // 13),
        "member run": "queryParams." * (size // 12),
        "vue query run": "push({query:{" * (size // 13),
        "url search run": "URLSearchParams((((" * (size // 19),
        "deep brackets": "navigate([" + "[" * size,
        "string soup": "navigate(['" + "\\'" * (size // 2),
        "no anchor": "queryParam navigat quer: route.quer " * (size // 36),
    }


def _time(body: str) -> float:
    start = time.perf_counter()
    spa.scan_query_params(body, max_bytes=8 * len(body) + 1)
    return time.perf_counter() - start


#: The generous CI bound for one 4 MB adversarial body (seconds).
SCAN_BOUND_S = 10.0


def test_the_scan_is_linear_on_4mb_adversarial_bodies(capsys):
    """B1 / PA-0095: each 4 MB near-miss body is scanned under a generous bound, and
    doubling a body (below the anchor cap) at most roughly doubles the time."""
    big = 4 * 1024 * 1024
    times = {}
    for name, body in _near_misses(big).items():
        times[name] = _time(body)
        assert times[name] < SCAN_BOUND_S, name
    with capsys.disabled():
        print("\nFR-CRAWL-17 scan, 4 MB adversarial bodies (s): "
              + ", ".join(f"{k} {v:.3f}" for k, v in times.items()))
    small, large = (_near_misses(256 * 1024)["no anchor"],
                    _near_misses(512 * 1024)["no anchor"])
    t_small = min(_time(small) for _ in range(3))
    t_large = min(_time(large) for _ in range(3))
    assert t_large < 3.5 * max(t_small, 1e-3)


# =====================================================================================
# Q3: seeds and their gates
# =====================================================================================
def test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path():
    url = spa.seed_url("http://h/#/login", ["redirectUrl", "q", "next", "returnTo"])
    assert url == "http://h/#/login?redirectUrl=/&q=fuzzlab&next=/&returnTo=/"
    assert spa.query_filler() == spa.filler("text") == "fuzzlab"
    assert spa.seed_url("http://h/app/search", ["q"]) == "http://h/app/search?q=fuzzlab"
    # whole tokens of the one shared open-redirect name set (PA-0003)
    from fuzzlab.tools.fetcher import REDIRECT_PARAMS
    assert all(spa.redirect_name(n) for n in REDIRECT_PARAMS)
    assert not any(spa.redirect_name(n) for n in ("q", "id", "nextable", "urlish",
                                                  "returned", "term"))
    assert spa.redirect_name("nextUrl") and spa.redirect_name("redirect_to")


@pytest.mark.parametrize("url", [
    "http://h/#/logout?x=fuzzlab",                    # destructive route
    "http://h/#/items?delete=fuzzlab",                # destructive name
    "http://h/#/x?a=fuzzlab#/logout",                 # a second '#' hides nothing
    "http://h/#/basket?checkout=fuzzlab",             # a transaction
    "http://h/#/profile?reset=fuzzlab",               # an account action in the fragment
    "http://h/#/x?newPassword=fuzzlab",               # a credential token in the fragment
    "http://h/logout?x=fuzzlab",                      # history mode
])
def test_the_seed_gate_refuses(url):
    assert spa.query_url_refusal(url) is not None


def test_the_seed_gate_passes_an_ordinary_seed():
    assert spa.query_url_refusal("http://h/#/track-result?id=fuzzlab") is None
    assert spa.query_url_refusal("http://h/#/login?redirectUrl=/") is None


# =====================================================================================
# Q5: markers and their attribution
# =====================================================================================
def test_no_marker_the_generator_can_emit_looks_like_an_identifier():
    """Pinned (A-M3): markers are letters only, lower case, fixed length and fresh per
    load, so every one is word-shaped and never `looks_like_identifier`. The alphabet
    and length are the generator's own constants (PA-0001); 20 000 drawn markers and the
    highest-entropy strings of that shape are checked."""
    assert set(spa.MARKER_ALPHABET) == set(string.ascii_lowercase)
    assert set(spa.MARKER_PREFIX) <= set(spa.MARKER_ALPHABET)
    drawn = [m for _ in range(20000 // spa.MAX_UNPAIRED_NAMES)
             for m in spa.mint_markers(spa.MAX_UNPAIRED_NAMES)]
    assert {len(m) for m in drawn} == {spa.MARKER_LEN}
    assert all(set(m) <= set(spa.MARKER_ALPHABET) for m in drawn)
    assert not any(looks_like_identifier(m) for m in drawn)
    extremes = [spa.MARKER_PREFIX + "".join(random.sample(spa.MARKER_ALPHABET,
                                                          spa.MARKER_LEN - 3))
                for _ in range(200)] + [spa.MARKER_PREFIX + "z" * (spa.MARKER_LEN - 3)]
    assert not any(looks_like_identifier(m) for m in extremes)


def test_markers_are_fresh_per_load_and_fixed_width():
    a, b = spa.mint_markers(3), spa.mint_markers(3)
    assert a != b and len(set(a)) == 3
    assert [m[3:5] for m in a] == ["aa", "ab", "ac"] == [m[3:5] for m in b]
    with pytest.raises(ValueError):
        spa.mint_markers(spa.MAX_UNPAIRED_NAMES + 1)


def _attr(texts, requests=(), names=("q", "extra")):
    markers = {m: n for m, n in zip(spa.mint_markers(len(names)), names)}
    by_name = {n: m for m, n in markers.items()}
    texts = [t.format(**by_name) for t in texts]
    requests = [(u.format(**by_name), b.format(**by_name)) for u, b in requests]
    return spa.observed_names(texts, requests, markers, list(names))


def test_two_names_one_reflected():
    assert _attr(["Results for {q}", "unrelated"]) == ({"q"}, 0)


def test_a_url_self_echo_keeps_nothing():
    """B5: ``location.href`` in a link (both markers, ``name=`` syntax), a canonical URL,
    a ``<base>``."""
    assert _attr(["http://h/#/r?q={q}&extra={extra}"]) == (set(), 0)
    assert _attr(["http://h/#/r?q={q}"]) == (set(), 0)
    assert _attr(["{q} {extra}"]) == (set(), 0)


def test_a_stale_marker_from_an_earlier_load_is_never_attributed():
    old = spa.mint_markers(1)[0]                        # load 1's marker for "q"
    markers = {spa.mint_markers(1)[0]: "q"}             # load 2's
    assert spa.observed_names([f"Last: {old}"], [], markers, ["q"]) == (set(), 0)


def test_boundaries_requests_and_the_path_count():
    assert _attr(["x{q}y"]) == (set(), 0)                         # inside a word
    assert _attr(["({q})"]) == ({"q"}, 0)
    assert _attr([], [("http://h/rest/lookup?k={q}", "")]) == ({"q"}, 0)
    assert _attr([], [("http://h/rest/item/{q}", "")]) == ({"q"}, 1)   # Q6 residual
    assert _attr([], [("http://h/api/beacon", "v={extra}")]) == ({"extra"}, 0)
    assert _attr([], [("http://h/rest/x?q={q}", "")]) == (set(), 0)      # name= echo
    assert _attr([], [("http://h/rest/x?k=%66zq", "")]) == (set(), 0)
    long = "a " * spa.MAX_OBSERVED_STRING + "{q}"
    assert _attr([long]) == (set(), 0)                           # too long: fail closed


# =====================================================================================
# Real browser: the fake app (tests/_spa_query_fixture.py)
# =====================================================================================
def _crawl(lab, path, **kw):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider(lab.base, max_depth=2, db_name=str(path), engine="playwright",
                     timeout_ms=10000, **kw)
    run_crawl(sp)
    return sp


def _import(db, path):
    from fuzzlab.core.store import Store
    from fuzzlab.tools import store_adapter
    store = Store(str(path))
    run = store.start_run("crawler", "spa-query")
    counts = store_adapter.import_spider(str(db), store, run)
    return store, run, counts


def _params(store, run):
    return {(r["url"], r["name"], r["location"]) for r in store.conn.execute(
        "SELECT e.url, p.name, p.location FROM parameter p JOIN endpoint e "
        "ON e.id = p.endpoint_id WHERE p.run_id = ?", (run,))}


@pytest.fixture(scope="module")
def query_crawl(tmp_path_factory):
    """One crawl of `QuerySpa` shared by the observation tests (a crawl with probes
    takes a while)."""
    with pytest.MonkeyPatch.context() as mp:
        chromium_or_skip(mp)
        other = Recorder()
        lab = QuerySpa(other_port=other.server.server_address[1])
        tmp = tmp_path_factory.mktemp("spaq")
        try:
            sp = _crawl(lab, tmp / "s.db")
            store, run, counts = _import(tmp / "s.db", tmp / "u.db")
            yield {"lab": lab, "other": other, "sp": sp, "db": str(tmp / "s.db"),
                   "store": store, "run": run, "counts": counts,
                   "store_path": str(tmp / "u.db")}
            store.close()
        finally:
            lab.close()
            other.close()


def _pages(db):
    return [u for (u,) in db_rows(db, "SELECT url FROM discovered_pages ORDER BY rowid")]


def test_paired_seeds_are_visited_after_their_bare_route_as_fragment_points(query_crawl):
    lab, db = query_crawl["lab"], query_crawl["db"]
    pages = _pages(db)
    base = lab.base
    for seed in ("#/track?id=fuzzlab", "#/score-board?q=fuzzlab", "#/poster?msg=fuzzlab",
                 "#/hop?go=fuzzlab", "#/away?page=fuzzlab", "#/login?redirectUrl=/"):
        assert base + seed in pages, seed
    # B8: the seed is visited after its bare route
    assert pages.index(base + "#/score-board") < pages.index(base + "#/score-board?q=fuzzlab")
    assert pages.index(base + "#/track") < pages.index(base + "#/track?id=fuzzlab")
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert sources[base + "#/track?id=fuzzlab"] == spa.SEED_SOURCE
    params = _params(query_crawl["store"], query_crawl["run"])
    for route, name in (("track", "id"), ("search", "q"), ("score-board", "q"),
                        ("poster", "msg")):
        assert (f"/#/{route}", name, "fragment") in params, route
    c = query_crawl["sp"].spa_counts
    assert c["spa_query_pairs"] == 8          # track..login + logout:bye (refused later)
    assert c["spa_query_seeded"] == c["spa_query_seeded_fragment"] >= 9


def test_search_and_score_board_q_stay_two_points_and_one_parameter_each(query_crawl):
    """B8: the same name on two routes is two points (and two findings); A-N2: a seed
    equal to a navigation the crawl already made (``#/search?q=fuzzlab``, a link here)
    is that page, so ``#/search`` has one ``q``."""
    from fuzzlab.harness.auto import injection_points_from_store
    store, run, lab = query_crawl["store"], query_crawl["run"], query_crawl["lab"]
    pages = _pages(query_crawl["db"])
    assert pages.count(lab.base + "#/search?q=fuzzlab") == 1
    rows = store.conn.execute(
        "SELECT COUNT(*) c FROM parameter p JOIN endpoint e ON e.id = p.endpoint_id "
        "WHERE p.run_id = ? AND e.url = '/#/search' AND p.name = 'q'", (run,)).fetchone()
    assert rows["c"] == 1
    pts = injection_points_from_store(store, run, lab.base, skipped=[],
                                      browser_available=True)
    q_points = {(p.url, p.location) for p in pts if p.param == "q"}
    assert q_points == {(lab.base + "#/search", "fragment"),
                        (lab.base + "#/score-board", "fragment")}


def test_two_findings_for_two_routes_sharing_a_name(query_crawl, tmp_path):
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.oracle.browser import ExecObservation
    from fuzzlab.tools.probesender import RequestsProbeSender
    lab = query_crawl["lab"]
    store, run, _c = _import(query_crawl["db"], tmp_path / "f.db")

    class Executor:
        def run(self, request, token):
            return ExecObservation(request.location == "fragment" and request.param == "q"
                                   and token in (request.value or ""))

    import requests
    with store, contextlib.closing(requests.Session()) as session:
        run_auto(base_url=lab.base, store=store, run_id=run,
                 sender=RequestsProbeSender(session=session), mode="manual",
                 selected_categories=["xss"], points_source="crawl", browser=Executor())
        found = {(r["url"], r["param"]) for r in store.conn.execute(
            "SELECT url, param FROM finding WHERE run_id=?", (run,))}
    assert {("/#/search", "q"), ("/#/score-board", "q")} <= found


def test_a_seed_load_cannot_write(query_crawl):
    """Q4: ``#/poster?msg=`` POSTs on load; inside the seed's window the server gets
    none (counted)."""
    lab = query_crawl["lab"]
    assert lab.seen("POST", "/api/send") == []
    assert query_crawl["sp"].spa_counts["spa_query_writes_blocked"] >= 1


def test_a_seeds_navigations_are_queued_never_followed_in_its_window(query_crawl):
    """Q4: ``#/hop?go=`` sets ``location.hash`` on load and ``#/away?page=`` navigates to
    ``/plain``: both targets are queued and visited as pages of their own."""
    lab, db = query_crawl["lab"], query_crawl["db"]
    rows = {u: (src, depth) for u, src, depth in
            db_rows(db, "SELECT url, source, depth FROM discovered_pages")}
    # queued one level below the seed (depth 1), never followed inside its load
    assert rows.get(lab.base + "#/landed") == ("redirect", 2)
    assert rows.get(lab.base + "plain") == ("redirect", 2)
    assert rows[lab.base + "#/hop?go=fuzzlab"][1] == 1


def test_a_destructive_seed_is_never_visited_and_a_redirect_name_stays_on_origin(
        query_crawl):
    lab, db, sp = query_crawl["lab"], query_crawl["db"], query_crawl["sp"]
    pages = _pages(db)
    assert not any("logout" in u for u in pages)
    assert lab.seen("GET", "/rest/marker/LOGOUT") == []
    assert lab.base + "#/login?redirectUrl=/" in pages      # never the filler
    assert query_crawl["other"].requests == []               # nothing left the origin
    assert sp.spa_query_refused.get("destructive route") == 1
    assert sp.spa_query_refused.get(spa.Q_DYNAMIC) == 1
    assert sp.spa_query_refused.get(spa.Q_SENSITIVE) == 1
    stats = dict(db_rows(db, "SELECT name, value FROM crawl_stats"))
    assert stats["spa_query_refused[destructive route]"] == 1
    assert stats["spa_query_refused"] == sp.spa_counts["spa_query_refused"]


def test_the_probe_keeps_only_observed_names(query_crawl):
    """Q5: ``term`` is kept where this load's marker is seen -- rendered (``reflect``),
    in a GET query (``fetcher``) or path (``pathy``), in an aborted POST's body
    (``beacon``) -- and nowhere else: ignored, self-echoed in a link (``echohref``),
    stashed (``save``) or replayed stale (``show``). ``extra`` is never shown; the
    redirect-ish ``next`` carries ``/``, no marker."""
    lab, db, sp = query_crawl["lab"], query_crawl["db"], query_crawl["sp"]
    pages = set(_pages(db))
    for kept in ("reflect", "fetcher", "pathy", "beacon"):
        assert lab.base + f"#/{kept}?term=fuzzlab" in pages, kept
    seeded = {u for u in pages if "?" in u.partition("#")[2]}
    for dropped in ("ignore", "echohref", "save", "show"):
        assert not any(f"#/{dropped}?" in u for u in seeded), dropped
    assert not any("extra=" in u or "next=" in u for u in pages)
    c = sp.spa_counts
    assert c["spa_query_unpaired"] == 3 and c["spa_query_kept"] == 4
    assert c["spa_query_probe_loads"] == 15                 # every rendered route once
    assert c["spa_query_marker_in_path"] >= 2   # pathy: its probe's marker, its seed's filler
    assert lab.seen("POST", "/api/beacon") == []            # aborted, still observed
    # Q6: the seeded visit's GET XHR is a query point; a path segment gives none
    params = _params(query_crawl["store"], query_crawl["run"])
    assert ("/rest/lookup", "k", "query") in params
    assert not any(u.startswith("/rest/item") for u, _n, _l in params)


def test_no_stored_row_carries_a_marker(query_crawl):
    """A-M3 / B3: a probe load records nothing -- no page, request, form, XHR URL or
    count carries a marker, in the spider DB or the store."""
    assert spa.MARKER_PREFIX not in db_text(query_crawl["db"])
    assert spa.MARKER_PREFIX not in db_text(query_crawl["store_path"])
    # ...while the probes did run with markers (the server saw them)
    assert any(spa.MARKER_PREFIX in r[1] for r in query_crawl["lab"].requests)


def test_the_summary_reports_kept_vs_confirmable_without_a_browser(query_crawl):
    sp = query_crawl["sp"]
    (line,) = [ln for ln in sp.spa_summary() if ln.startswith("SPA query parameters (")]
    c = sp.spa_counts
    assert (f"{c['spa_query_seeded_fragment']} hash route(s) (fragment points, "
            f"confirmable only with --browser) and 0 history route(s)") in line
    assert any(ln.startswith("SPA query parameters refused:") for ln in sp.spa_summary())
    stats = dict(db_rows(query_crawl["db"], "SELECT name, value FROM crawl_stats"))
    assert all(stats[k] == v for k, v in c.items())


def test_two_crawls_give_the_same_pages_endpoints_and_parameters(query_crawl, tmp_path):
    lab = query_crawl["lab"]
    _crawl(lab, tmp_path / "s2.db")
    store, run, _c = _import(tmp_path / "s2.db", tmp_path / "u2.db")
    with store:
        again = (_params(store, run),
                 {r["url"] for r in store.conn.execute(
                     "SELECT url FROM endpoint WHERE run_id=?", (run,))},
                 {r["url"] for r in store.conn.execute(
                     "SELECT url FROM page WHERE run_id=?", (run,))})
    first_store, first_run = query_crawl["store"], query_crawl["run"]
    first = (_params(first_store, first_run),
             {r["url"] for r in first_store.conn.execute(
                 "SELECT url FROM endpoint WHERE run_id=?", (first_run,))},
             {r["url"] for r in first_store.conn.execute(
                 "SELECT url FROM page WHERE run_id=?", (first_run,))})
    assert again == first


def test_the_switch_turns_query_discovery_off(query_crawl, tmp_path):
    """PA-0089: off, no seed and no probe; the bare routes are crawled as before."""
    lab = query_crawl["lab"]
    lab.requests.clear()
    sp = _crawl(lab, tmp_path / "off.db", spa_query=False)
    pages = _pages(str(tmp_path / "off.db"))
    assert lab.base + "#/track" in pages
    assert not any("?" in u.partition("#")[2] for u in pages
                   if "#/search?" not in u)
    assert sp.spa_counts["spa_query_probe_loads"] == 0
    assert not any(spa.MARKER_PREFIX in r[1] for r in lab.requests)


# =====================================================================================
# End to end: #/track-result?id= -> a fragment point -> M6 confirms DOM XSS (--browser)
# =====================================================================================
def _m6_run(lab, tmp_path, **crawl_kw):
    import requests

    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    from fuzzlab.tools.probesender import RequestsProbeSender
    _crawl(lab, tmp_path / "s.db", **crawl_kw)
    store, run, _c = _import(tmp_path / "s.db", tmp_path / "u.db")
    with store:
        params = _params(store, run)
        session = requests.Session()
        with contextlib.closing(session):
            run_auto(base_url=lab.base, store=store, run_id=run,
                     sender=RequestsProbeSender(session=session), mode="manual",
                     selected_categories=["xss"], points_source="crawl",
                     browser=PlaywrightBrowserExecutor())
        found = {(r["url"], r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT url, param, vuln_class FROM finding WHERE run_id=?", (run,))}
    return params, found


def test_track_result_id_reaches_m6_and_confirms_dom_xss(monkeypatch, tmp_path):
    """The live gap, end to end in a real browser: the bundle's
    ``navigate([`/track-result`],{queryParams:{id:t}})`` seeds ``#/track-result?id=``,
    the importer makes it a fragment point, and M6 confirms DOM XSS there. Without the
    query discovery (the mutation) no such point exists and nothing is found."""
    chromium_or_skip(monkeypatch)
    lab = TrackSpa()
    try:
        params, found = _m6_run(lab, tmp_path)
        assert ("/#/track-result", "id", "fragment") in params
        assert ("/#/track-result", "id", "xss-dom") in found
        (tmp_path / "off").mkdir()
        off_params, off_found = _m6_run(lab, tmp_path / "off", spa_query=False)
        assert not any(n == "id" for _u, n, _l in off_params)
        assert off_found == set()
    finally:
        lab.close()
