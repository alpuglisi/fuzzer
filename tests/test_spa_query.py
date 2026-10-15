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


def test_names_are_capped():
    many = "".join(f"r.queryParams.n{i};" for i in range(spa.MAX_QUERY_NAMES + 7))
    q = spa.scan_query_params(many)
    assert len(q.unpaired) == spa.MAX_QUERY_NAMES
    assert q.refused == {spa.Q_NAME_CAP: 7}


def test_cheap_noise_anchors_never_hide_a_later_pair():
    """S4 (review A-S1): the budget is on the walker's steps, not the anchor count, so
    3000 O(1) noise anchors cost O(1) each and the real pair after them is found."""
    body = "navigate(x);" * 3000 + "this.router.navigate([`/t`],{queryParams:{id:t}})"
    q = spa.scan_query_params(body)
    assert q.pairs == {"t": ["id"]} and not q.budget_hit and q.anchors == 3001


def test_the_step_budget_is_enforced_and_counted():
    body = "navigate([`/a`],{queryParams:{x" * 2000 + "r.queryParams.late;"
    q = spa.scan_query_params(body, budget=20_000)
    assert q.budget_hit and q.steps <= 20_000 + spa.QUERY_WINDOW
    assert "late" not in q.unpaired
    assert not spa.scan_query_params(body).budget_hit           # the default budget


def test_relative_navigations_and_dot_segments_name_no_route():
    """S5 (review A-S2): ``relativeTo`` makes the route relative -- its names are
    unpaired; a ``.`` / ``..`` segment is never a route."""
    assert _scan("navigate([`child`],{relativeTo:this.route,queryParams:{tab:t}})") == (
        {}, ["tab"], {})
    for path in (".", "..", "./x", "a/../b", "#/./a"):
        assert spa.classify_route(path)[0] == spa.ROUTE_INVALID, path


@pytest.mark.parametrize("body", [
    "navigate([`./rel`],{queryParams:{dot:t}})",
    "navigate(['..'],{queryParams:{dot:t}})",
    "navigate(['a','..','b'],{queryParams:{dot:t}})",
    "this.$router.push({path:'../up',query:{dot:1}})",
    "navigate('./x?dot=1')",
    "navigateByUrl(`../x?dot=1`)",
])
def test_a_relative_dot_segment_route_is_dropped_at_the_scan(body):
    """U7 (review A2-S3): a ``.`` / ``..`` route names no route: no pair is counted (that
    `classify_route` would refuse later); its names are unpaired."""
    assert _scan(body) == ({}, ["dot"], {})


def test_navigate_by_url_hyphenated_keys_and_longer_names():
    """S11: ``navigateByUrl`` literals pair (A-N1); a dropped quoted key that is not
    identifier-shaped is counted (A-N2); ``myqueryParams:{`` is not an anchor (A-N4)."""
    assert _scan("this.router.navigateByUrl(`/basket?tab=open`);navigateByUrl(t)") == (
        {"/basket": ["tab"]}, [], {})
    assert _scan("navigate(['/r'],{queryParams:{'a-b':1,ok:2}})") == (
        {"r": ["ok"]}, [], {spa.Q_SHAPE: 1})
    assert _scan("x.myqueryParams:{a:1}; myqueryParams.b; z.queryParams.c") == (
        {}, ["c"], {})


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
    """Adversarial bodies: every anchor repeated as a near miss, and reviewer A's
    shapes (a long route array, cheap noise anchors)."""
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
        "long route array": ("navigate([" + "`a`," * 126 + "]") * (size // 515),
        "noise anchors": "navigate(x);" * (size // 12),
    }


#: The absolute smoke bound for one 4 MB adversarial body (seconds): a gross-regression
#: alarm only; the complexity is asserted on operation counts (PA-0135).
SCAN_BOUND_S = 10.0
#: Shapes with O(1) anchors, so O(1) work whatever their length (stated, U5): the
#: doubling oracle checks them for constancy instead.
CONSTANT_SHAPES = frozenset({"deep brackets", "string soup", "no anchor"})
#: The 4 MB shapes whose walk the step budget stops (asserted, U5).
BUDGET_SHAPES = frozenset({"long route array", "navigate run", "unclosed options",
                           "vue query run"})
#: Steps per character on a 4 MB body that the budget does not stop (U5).
STEPS_PER_CHAR = 0.25
#: The doubling oracle's sizes, its factor and its additive slack (U5, review A2-M2):
#: ``ops(2n) <= 2.1 * ops(n) + 2 * QUERY_WINDOW``, at sizes where a quadratic walker's
#: extra steps dwarf the slack.
DOUBLING_SIZES = (64 * 1024, 128 * 1024)
DOUBLING_FACTOR = 2.1
DOUBLING_SLACK = 2 * spa.QUERY_WINDOW
#: A finite budget for the oracle's runs: a linear scan of 128 KB stays far under it
#: (the heaviest shape, vue, ~5.2 M steps); a quadratic one hits it and fails.
DOUBLING_BUDGET = 10_000_000


def test_the_scan_stays_within_its_step_budget_on_4mb_adversarial_bodies(capsys):
    """BUG-0135 / PA-0135 (U5): on each 4 MB near-miss body, the four shapes whose walk
    is heavy hit the step budget (and stop within one window of it); every other shape
    stays under `STEPS_PER_CHAR` steps per character without hitting it; the monotone
    ``str.find`` covers the body at most once per anchor kind. The wall-clock time is
    only a smoke bound."""
    big = 4 * 1024 * 1024
    times = {}
    for name, body in _near_misses(big).items():
        start = time.perf_counter()
        q = spa.scan_query_params(body, max_bytes=8 * len(body) + 1)
        times[name] = time.perf_counter() - start
        if name in BUDGET_SHAPES:
            assert q.budget_hit, name
            assert q.steps <= spa.MAX_QUERY_STEPS + spa.QUERY_WINDOW, name
        else:
            assert not q.budget_hit, name
            assert q.steps <= STEPS_PER_CHAR * len(body), (name, q.steps)
        assert q.scanned <= len(spa._QUERY_ANCHORS) * (len(body) + 1) + \
            2 * spa.QUERY_WINDOW * q.anchors, name
        assert times[name] < SCAN_BOUND_S, name
    with capsys.disabled():
        print("\nFR-CRAWL-17 scan, 4 MB adversarial bodies (s): "
              + ", ".join(f"{k} {v:.3f}" for k, v in times.items()))


@pytest.mark.parametrize("shape", sorted(set(_near_misses(1024)) - CONSTANT_SHAPES))
def test_doubling_a_body_at_most_doubles_the_operations(shape):
    """BUG-0135 / PA-0135 (operation-count oracle, U5): for every shape whose work
    grows, ``ops(2n) <= 2.1 * ops(n) + 2 * QUERY_WINDOW`` for both the walker's steps and
    the characters ``str.find`` covered, at 64 / 128 KB, and neither run hits the
    oracle's budget. A quadratic walker fails this on every such shape, whatever the
    machine's load (proven by mutation, CC-CRAWL-0027)."""
    small, large = (_near_misses(n)[shape] for n in DOUBLING_SIZES)
    a = spa.scan_query_params(small, budget=DOUBLING_BUDGET)
    b = spa.scan_query_params(large, budget=DOUBLING_BUDGET)
    assert not a.budget_hit and not b.budget_hit, (a.steps, b.steps)
    assert b.steps <= DOUBLING_FACTOR * a.steps + DOUBLING_SLACK, (a.steps, b.steps)
    assert b.scanned <= DOUBLING_FACTOR * a.scanned + DOUBLING_SLACK, (a.scanned, b.scanned)


@pytest.mark.parametrize("shape", sorted(CONSTANT_SHAPES))
def test_a_shape_with_constant_anchors_does_constant_work(shape):
    """U5: the stated constant shapes really are constant."""
    small, large = (_near_misses(n)[shape] for n in DOUBLING_SIZES)
    a = spa.scan_query_params(small, budget=DOUBLING_BUDGET)
    b = spa.scan_query_params(large, budget=DOUBLING_BUDGET)
    assert a.steps == b.steps and a.anchors == b.anchors <= 1


# =====================================================================================
# Q3: seeds and their gates
# =====================================================================================
def test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path():
    url = spa.seed_url("http://h/#/login", ["redirectUrl", "q", "next", "returnTo"])
    assert url == "http://h/#/login?redirectUrl=/&q=fuzzlab&next=/&returnTo=/"
    assert spa.query_filler() == spa.filler("text") == "fuzzlab"
    assert spa.seed_url("http://h/app/search", ["q"]) == "http://h/app/search?q=fuzzlab"
    # whole tokens of the one shared open-redirect name set (PA-0003), in core since
    # CC-CORE-0053; the auditor's rule reads the same object
    from fuzzlab.core.urls import REDIRECT_PARAMS
    from fuzzlab.tools import fetcher
    assert fetcher.REDIRECT_PARAMS is REDIRECT_PARAMS
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


def _attr(texts, requests=(), names=("q", "extra"), **kw):
    markers = {m: n for m, n in zip(spa.mint_markers(len(names)), names)}
    by_name = {n: m for m, n in markers.items()}
    texts = [t.format(**by_name) for t in texts]
    requests = [(r[0].format(**by_name), r[1].format(**by_name), *r[2:])
                for r in requests]
    kw.setdefault("doc_path", "/")
    kw.setdefault("route", "#/r")
    return spa.observed_names(texts, requests, markers, list(names), **kw)


def test_two_names_one_reflected():
    assert _attr(["Results for {q}", "unrelated"]) == ({"q"}, 0)


def test_a_url_self_echo_keeps_nothing():
    """B5: ``location.href`` in a link (both markers, ``name=`` syntax), a canonical URL,
    a ``<base>``."""
    assert _attr(["http://h/#/r?q={q}&extra={extra}"]) == (set(), 0)
    assert _attr(["http://h/#/r?q={q}"]) == (set(), 0)
    assert _attr(["{q} {extra}"]) == (set(), 0)


def test_a_single_name_location_href_echo_keeps_nothing():
    """S6: the DOM's ``<a href>`` copy of ``location.href`` with one probed name."""
    assert _attr(["http://h/#/r?q={q}"], names=("q",)) == (set(), 0)


def test_a_blocked_request_is_never_evidence():
    """S1 (review A-M1): a name whose only evidence is a request the window or the guard
    aborted is not kept; the same request completed keeps it."""
    assert _attr([], [("http://h/api/beacon", "v={q}", True)]) == (set(), 0)
    assert _attr([], [("http://h/rest/lookup?k={q}", "", True)]) == (set(), 0)
    assert _attr([], [("http://h/rest/lookup?k={q}", "", False)]) == ({"q"}, 0)


def test_markers_are_scrubbed_to_a_fixed_placeholder():
    """S7 (review A-S4): any whole-token marker, never a longer word that contains one."""
    m = spa.mint_markers(1)[0]
    assert spa.scrub_markers(f"Last: {m}; ?q={m}") == \
        f"Last: {spa.MARKER_PLACEHOLDER}; ?q={spa.MARKER_PLACEHOLDER}"
    assert spa.scrub_markers(f"x{m}") == f"x{m}" and spa.scrub_markers(m + "s") == m + "s"
    assert spa.MARKER_PREFIX not in spa.MARKER_PLACEHOLDER
    assert spa.scrub_markers(None) is None and spa.scrub_markers(7) == 7


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
    # S6: an API forwarding the name keeps it; a copy of the page's own URL does not
    assert _attr([], [("http://h/api/search?q={q}", "")]) == ({"q"}, 0)
    assert _attr([], [("http://h/?q={q}", "")]) == (set(), 0)          # the document
    assert _attr([], [("http://h/log?u=http://h/%23/r%3Fq%3D{q}", "")]) == (set(), 0)
    assert _attr([], [("http://h/app/?q={q}", "")], doc_path="/app/") == (set(), 0)
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
            with pytest.MonkeyPatch.context() as spy:
                windows = _window_spy(spy)      # P1: what each query window saw
                sp = _crawl(lab, tmp / "s.db")
            # M10: this crawl's own requests, before any other test crawls the lab
            first = list(lab.requests)
            store, run, counts = _import(tmp / "s.db", tmp / "u.db")
            yield {"lab": lab, "other": other, "sp": sp, "db": str(tmp / "s.db"),
                   "first_requests": first, "windows": windows,
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
    for route, name in (("track", "id"), ("search", "q"), ("score-board", "q")):
        assert (f"/#/{route}", name, "fragment") in params, route
    c = query_crawl["sp"].spa_counts
    # track..login, autopost, wsping, txn, hopper, and logout:bye (refused later); never
    # ./rel
    assert c["spa_query_pairs"] == 12
    assert c["spa_query_seeded"] == c["spa_query_seeded_fragment"] >= 9


def test_a_request_whose_redirect_hop_was_refused_is_never_fetched_again(query_crawl):
    """Y1 (review A3-S1 / B3-S1): ``#/hopper?x=`` fetches ``/api/go``, which redirects
    to a transaction GET the window refuses: the request fails, so it is blocked for the
    window -- never queued from the load's request list, never fetched again outside
    the window (where its hop would run), never stored. Reads the first crawl's own
    requests (M10), whatever other test crawled the lab since."""
    lab, db = query_crawl["lab"], query_crawl["db"]
    first = query_crawl["first_requests"]
    assert not any(r[1].startswith("/api/order/confirm") for r in first)
    assert len([r for r in first if r[0] == "GET" and r[1] == "/api/go"]) == 1
    assert not any("/api/go" in u for u in _pages(db))
    assert lab.base + "#/hopper?x=fuzzlab" in _pages(db)


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
    """Q5: ``term`` is kept where this load's marker is seen -- rendered (``reflect``,
    ``memo``), in a completed GET's query under another name (``fetcher``) or the same
    name (``forward``, S6) or its path (``pathy``) -- and nowhere else: ignored,
    self-echoed in a link (``echohref``), stashed (``save``), replayed stale
    (``show``), or only in a POST the window blocked (``beacon``, S1). ``extra`` is never
    shown; the redirect-ish ``next`` carries ``/``, no marker."""
    lab, db, sp = query_crawl["lab"], query_crawl["db"], query_crawl["sp"]
    pages = set(_pages(db))
    for kept in ("reflect", "memo", "fetcher", "forward", "pathy"):
        assert lab.base + f"#/{kept}?term=fuzzlab" in pages, kept
    seeded = {u for u in pages if "?" in u.partition("#")[2]}
    for dropped in ("ignore", "echohref", "save", "show", "beacon"):
        assert not any(f"#/{dropped}?" in u for u in seeded), dropped
    assert not any("extra=" in u or "next=" in u for u in pages)
    c = sp.spa_counts
    # term, extra, next, and dot (from ``./rel``: a relative route names none, U7)
    assert c["spa_query_unpaired"] == 4 and c["spa_query_kept"] == 5
    assert c["spa_query_probe_loads"] == 21                 # every rendered route once
    assert c["spa_query_marker_in_path"] >= 2   # pathy: its probe's marker, its seed's filler
    assert lab.seen("POST", "/api/beacon") == []            # blocked, never evidence
    # Q6: the seeded visit's GET XHR is a query point; a path segment gives none
    params = _params(query_crawl["store"], query_crawl["run"])
    assert ("/rest/lookup", "k", "query") in params
    assert not any(u.startswith("/rest/item") for u, _n, _l in params)


def test_no_stored_row_carries_a_marker(query_crawl):
    """A-M3 / B3: a probe load records nothing -- no page, request, form, XHR URL or
    count carries a marker, in the spider DB or the store."""
    assert spa.MARKER_PREFIX not in db_text(query_crawl["db"])
    assert spa.MARKER_PREFIX not in db_text(query_crawl["store_path"])
    # S7: ``memo``'s seed, visited after the probes, showed ``save``'s stashed marker;
    # the storage boundary replaced it
    content = dict(db_rows(query_crawl["db"], "SELECT url, content FROM discovered_pages"))
    assert spa.MARKER_PLACEHOLDER in content[query_crawl["lab"].base + "#/memo?term=fuzzlab"]
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


def test_a_seed_that_blocked_a_write_is_never_a_point_and_m6_never_sends_it(
        query_crawl, tmp_path, monkeypatch):
    """S1 (review A-M1): ``#/poster?msg=`` POSTs on load. Its seed's window blocked the
    write, so the seed is kept as a page (``source = 'spa-query-writes'``) but is never a
    point, and ``beacon``, whose only evidence was the blocked POST, is never kept: a
    later M6 run (real browser, outside any window) never loads them, so the server sees
    no POST to ``/api/send`` or ``/api/beacon`` -- through the crawl, the import and
    M6."""
    import requests

    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    from fuzzlab.tools.probesender import RequestsProbeSender
    lab, db, sp = query_crawl["lab"], query_crawl["db"], query_crawl["sp"]
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    # U1: an auto-submitted POST navigation, a held WebSocket message and a transaction
    # GET the window refused are writes too
    for seed in ("#/poster?msg=fuzzlab", "#/autopost?go2=fuzzlab", "#/wsping?ping=fuzzlab",
                 "#/txn?ref=fuzzlab"):
        assert sources[lab.base + seed] == spa.WRITE_SEED_SOURCE, seed
    assert sources[lab.base + "#/track?id=fuzzlab"] == spa.SEED_SOURCE     # promoted
    assert sp.spa_counts["spa_query_write_seeds"] >= 4
    # Y2 (review B3-S2): every window closed cleanly, so these came from real writes
    assert sp.spa_counts["spa_query_unclean_windows"] == 0
    assert dict(db_rows(db, "SELECT name, value FROM crawl_stats"))[
        "spa_query_write_seeds"] >= 1
    monkeypatch.setattr("fuzzlab.tools.browserexec.PlaywrightBrowserExecutor.SETTLE_MS",
                        1000)                       # the fixture's sinks are synchronous
    store, run, counts = _import(db, tmp_path / "m6.db")
    with store, contextlib.closing(requests.Session()) as session:
        params = _params(store, run)
        assert counts["write_seed_skipped"] >= 1
        assert not any(u in ("/#/poster", "/#/beacon", "/#/autopost", "/#/wsping",
                             "/#/txn") for u, _n, _l in params)
        # the seeds and M6 are what this test is about: the writes the crawl recorded
        # (capture-and-abort) are probed by default (D67) and are opted out here, so
        # every POST below could only come from a seed or M6
        run_auto(base_url=lab.base, store=store, run_id=run,
                 sender=RequestsProbeSender(session=session), mode="manual",
                 selected_categories=["xss"], points_source="crawl",
                 browser=PlaywrightBrowserExecutor(), probe_captured_writes=False)
        found = {(r["url"], r["param"]) for r in store.conn.execute(
            "SELECT url, param FROM finding WHERE run_id=?", (run,))}
    assert ("/#/track", "id") in found                      # M6 did run
    assert lab.seen("POST", "/api/send") == [] and lab.seen("POST", "/api/beacon") == []
    assert lab.seen("POST", "/api/autopost") == []
    assert not any(m.startswith("ping-") for m in lab.ws_messages)
    # the window's refusals are never queued from the load's request list and fetched
    # outside it (found by this test in review round 2)
    assert lab.seen("GET", "/api/order/confirm") == [] and lab.seen("GET", "/api/send") == []
    assert lab.seen("GET", "/api/autopost") == []


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


# =====================================================================================
# Review round 1 (S9-S11): probe aborts, the session after a query load, the CLI flag
# =====================================================================================
def test_a_probes_aborted_url_is_blocked_evidence_never_a_skipped_destructive(tmp_path):
    """S9 (review B-S1): while a probe is open, a guard abort (destructive, out of
    scope) marks the URL blocked for that probe and is never recorded in
    ``skipped_destructive``; outside a probe it is recorded as before."""
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    try:
        sp._probe = {"blocked": set()}
        sp._note_guard_abort("http://127.0.0.1:9/logout?q=fzqaaabcdefgh", "logout")
        sp._note_out_of_scope("http://203.0.113.9/x?q=fzqaaabcdefgh")
        assert sp.skipped_destructive == {}
        assert sp._probe["blocked"] == {"http://127.0.0.1:9/logout?q=fzqaaabcdefgh",
                                        "http://203.0.113.9/x?q=fzqaaabcdefgh"}
        sp._probe = None
        sp._note_guard_abort("http://127.0.0.1:9/logout", "logout")
        assert sp.skipped_destructive == {"http://127.0.0.1:9/logout": "logout"}
    finally:
        sp.storage.close()


def test_the_cli_flag_turns_query_discovery_off():
    """S11 (review A-N3): ``--no-spa-query``."""
    from fuzzlab.tools.spider import build_parser
    assert build_parser().parse_args([]).no_spa_query is False
    assert build_parser().parse_args(["--no-spa-query"]).no_spa_query is True


def test_a_session_lost_in_a_query_load_stops_query_loads(monkeypatch, tmp_path):
    """S10 (review B-S4): in an authenticated crawl whose session is in localStorage, the
    ``fade`` seed clears the token client-side (no request). The window's client-side
    check sees it before the page leaves; seed and probe loads stop for the crawl (the
    ``after1`` seed is never loaded), the session is re-adopted on the start page and
    verified live, and the crawl goes on."""
    from tests.test_forms_phase4 import _LsManager
    from tests._spa_query_fixture import SessionQuerySpa
    chromium_or_skip(monkeypatch)
    lab = SessionQuerySpa()
    try:
        manager = _LsManager(lab.base)
        sp = _crawl(lab, tmp_path / "s.db", session_manager=manager, identity="user")
    finally:
        lab.close()
    gets = [r[1] for r in lab.seen("GET", "/rest/marker/")]
    assert "/rest/marker/fade-query" in gets                 # the seed that logs out
    assert "/rest/marker/after1-query" not in gets           # stopped
    assert "/rest/marker/after1" in gets                     # the bare route was crawled
    assert sp.spa_counts["spa_query_session_losses"] == 1
    assert sp.spa_query_stopped and "session was lost" in sp.spa_query_stopped
    assert sp.spa_query_refused.get("session lost", 0) >= 1
    assert not sp.reveals_stopped and not sp.spa_submit_stopped   # re-adopted
    assert manager.verified >= 1
    stats = dict(db_rows(str(tmp_path / "s.db"), "SELECT name, value FROM crawl_stats"))
    assert stats["spa_query_stopped"] == 1
    assert any(ln.startswith("SPA query loads stopped") for ln in sp.spa_summary())


# =====================================================================================
# Review round 2 (U1-U4, U9): what counts as a write, fail-closed filing, the session
# =====================================================================================
def _requests_spider(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    return LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "s.db"),
                       engine="requests")


def test_a_held_websocket_message_is_a_write(tmp_path):
    """U1: in a query window a dropped page-to-server WebSocket message counts as a
    write; in a reveal window it does not (that window has no write accounting)."""
    sp = _requests_spider(tmp_path)
    try:
        sp._win = {"query": spa.SEED_SOURCE, "aborted": 0}
        sp._note_ws_drop("ws://127.0.0.1:9/ws")
        assert sp._win["writes"] == 1
        sp._win = {"query": None, "aborted": 0}
        sp._note_ws_drop("ws://127.0.0.1:9/ws")
        assert "writes" not in sp._win
    finally:
        sp.storage.close()


@pytest.mark.parametrize("method,url,navigation,write", [
    ("POST", "http://127.0.0.1:9/api/autopost", True, True),     # a form's POST nav
    ("POST", "http://127.0.0.1:9/api/x", False, True),
    ("GET", "http://127.0.0.1:9/api/order/confirm", False, True),  # a word rule
    ("GET", "http://127.0.0.1:9/other", True, False),            # a navigation, queued
    # P2 (review B-S2): a navigation (or redirect hop) to a word-refused GET is a write,
    # never queued
    ("GET", "http://127.0.0.1:9/api/order/confirm?via=hop", True, True),
])
def test_what_a_query_window_counts_as_a_write(tmp_path, method, url, navigation, write):
    sp = _requests_spider(tmp_path)
    try:
        ctx = object()
        sp._win = {"context": ctx, "lifted_for": None, "own_nav": frozenset(),
                   "aborted": 0, "navs": [], "query": spa.SEED_SOURCE}
        assert sp._window_refusal(method, url, navigation, context=ctx) is not None
        assert bool(sp._win.get("writes")) is write
        # a refused POST navigation is a write, never a page to visit as a GET (A2-M1)
        assert sp._win["navs"] == ([url] if navigation and method == "GET" and not write
                                   else [])
        assert url in sp._win["blocked"]          # never queued from the request list
    finally:
        sp.storage.close()


class _FakeCtx:
    def __init__(self):
        self.jar = [{"name": "sid", "value": "S"}]
        self.pages = []

    def cookies(self):
        return list(self.jar)


class _FakePage:
    """Just enough of a page for a query window's exit; ``on_wait`` runs at each wait
    (the window's quiet period)."""

    def __init__(self, url, on_wait=None):
        self.url, self.on_wait = url, on_wait
        self.keyboard = type("K", (), {"press": lambda s, k: None})()

    def goto(self, url, **kw):
        self.url = url

    def on(self, event, fn):                      # navguard.navigate (BUG-0138)
        pass

    def wait_for_load_state(self, state, **kw):   # its bounded load wait
        pass

    def wait_for_timeout(self, ms):
        if self.on_wait is not None:
            self.on_wait()

    def evaluate(self, script, *a):
        return 0


def _session_spider(tmp_path, live=True):
    sp = _requests_spider(tmp_path)
    ctx = _FakeCtx()

    class Manager:
        verified = 0

        def verify_live(self, host, identity, base):
            Manager.verified += 1
            return live
    sp._authenticated, sp._context, sp._injected_cookies = True, ctx, [("sid", "S")]
    sp._session_manager, sp._identity = Manager(), "user"
    return sp, ctx, Manager


def test_a_cookie_cleared_while_the_page_leaves_is_a_loss(tmp_path):
    """U4 (review B2-S1): the cookie half of the check runs again after the window's
    quiet period; a credential cookie cleared by a response that landed while the page
    left is a loss, though the check before leaving passed."""
    sp, ctx, _m = _session_spider(tmp_path)
    try:
        page = _FakePage("http://127.0.0.1:9/#/x?a=fuzzlab",
                         on_wait=lambda: setattr(ctx, "jar", []))
        sp._doc_url, sp._load_committed = page.url, True     # the load committed (M6)
        with sp._window(page, ctx, page.url, query=spa.SEED_SOURCE) as win:
            pass
        assert win["session"][0] is False and "sid" in win["session"][1]
        assert win["closed"] and page.url == "about:blank"
    finally:
        sp.storage.close()


def test_the_session_is_rechecked_when_leaving_the_page_fails(tmp_path):
    """Y3 (review B3-S3): the page's ``about:blank`` fails (the window's failure path)
    after the jar was cleared: the re-check still runs there, so the window's verdict is
    a loss."""
    from fuzzlab.tools.spider import PlaywrightError
    sp, ctx, _m = _session_spider(tmp_path)

    class Page(_FakePage):
        def goto(self, url, **kw):
            if url == "about:blank":
                ctx.jar = []
                raise PlaywrightError("navigation failed")
            self.url = url
    try:
        page = Page("http://127.0.0.1:9/#/x?a=fuzzlab")
        sp._doc_url, sp._load_committed = page.url, True     # the load committed (M6)
        with sp._window(page, ctx, page.url, query=spa.SEED_SOURCE) as win:
            pass
        assert not win.get("closed")
        assert win["session"][0] is False and "sid" in win["session"][1]
    finally:
        sp.storage.close()


@pytest.mark.parametrize("live", [True, False])
def test_verify_live_runs_after_a_window_that_blocked_a_write(tmp_path, live):
    """U4 (review B2-S2, W4 parity): the server's verdict is asked only when the window
    blocked a write, and its "no" is a loss."""
    sp, ctx, manager = _session_spider(tmp_path, live=live)
    try:
        sp._doc_url = "http://127.0.0.1:9/#/x?a=1"   # each load committed (M6)
        sp._load_committed = True
        with sp._window(_FakePage("http://127.0.0.1:9/#/x?a=1"), ctx, "http://127.0.0.1:9/#/x?a=1",
                        query=spa.SEED_SOURCE) as win:
            pass
        assert manager.verified == 0 and win["session"] == (True, None)
        sp._doc_url = "http://127.0.0.1:9/#/y?a=1"
        with sp._window(_FakePage("http://127.0.0.1:9/#/y?a=1"), ctx, "http://127.0.0.1:9/#/y?a=1",
                        query=spa.SEED_SOURCE) as win:
            win["writes"] = 1
        assert manager.verified == 1 and win["session"][0] is live
    finally:
        sp.storage.close()


def test_the_cli_flags_reach_the_spider_through_one_builder():
    """U9 (review B-N1): ``__main__`` builds `LocalSpider`'s keywords with
    `spider_kwargs`; ``--no-spa-query`` reaches ``spa_query``, and every keyword the
    builder passes is one `LocalSpider` takes."""
    import inspect

    from fuzzlab.tools.spider import LocalSpider, build_parser, spider_kwargs
    on = spider_kwargs(build_parser().parse_args([]))
    off = spider_kwargs(build_parser().parse_args(["--no-spa-query"]))
    assert on["spa_query"] is True and off["spa_query"] is False
    params = set(inspect.signature(LocalSpider.__init__).parameters) - {"self", "start_url"}
    assert set(on) == params


def test_auth_origin_reaches_the_session_manager_through_the_builder(monkeypatch):
    """M0 (merge review): ``--auth-origin`` reaches `make_session_manager` through
    `session_manager_for`, the one builder ``__main__`` uses; no ``--identity``, no
    manager."""
    from fuzzlab.tools import authhttp
    from fuzzlab.tools.spider import parse_args, session_manager_for
    calls = []
    monkeypatch.setattr(authhttp, "make_session_manager",
                        lambda start, **kw: calls.append((start, kw)) or "MGR")
    assert session_manager_for(parse_args(["--start", "http://127.0.0.1:3000"])) is None
    args = parse_args(["--start", "http://127.0.0.1:3000", "--identity", "user",
                       "--store", "x.db", "--auth-origin", "http://127.0.0.1:3001"])
    assert session_manager_for(args) == "MGR"
    assert calls == [("http://127.0.0.1:3000",
                      {"store_path": "x.db", "auth_origins": args.auth_origin})]
    assert "http://127.0.0.1:3001" in str(args.auth_origin)


def test_a_revealed_forms_route_and_signature_are_scrubbed(tmp_path):
    """U9 (review B-N3): the route and signature are stored scrubbed, and the dedup
    reads the stored key."""
    sp = _requests_spider(tmp_path)
    try:
        m = spa.mint_markers(1)[0]
        assert sp.storage.record_revealed_form("http://h/#/r", f"r?q={m}", f"sig {m}")
        assert not sp.storage.record_revealed_form("http://h/#/r", f"r?q={m}", f"sig {m}")
        rows = sp.storage.cursor.execute(
            "SELECT route, signature FROM revealed_forms").fetchall()
        assert rows == [(f"r?q={spa.MARKER_PLACEHOLDER}", f"sig {spa.MARKER_PLACEHOLDER}")]
    finally:
        sp.storage.close()


def test_no_probe_is_planned_once_query_loads_stopped(tmp_path):
    """U9 (review B-N5)."""
    sp = _requests_spider(tmp_path)
    try:
        sp._query_on, sp._page = True, object()
        sp._query_unpaired = {"q": None}
        sp._probe_routes = {"a": ("http://127.0.0.1:9/#/a", 1)}
        sp.storage.mark_visited("http://127.0.0.1:9/#/a", 200, 1)
        assert sp._plan_probes() == [("http://127.0.0.1:9/#/a", 1, spa.PROBE_SOURCE)]
        sp._probed = set()
        sp.spa_query_stopped = "lost"
        assert sp._plan_probes() == []
    finally:
        sp.storage.close()


def test_a_seed_is_never_importable_until_its_window_closed_cleanly(monkeypatch, tmp_path):
    """U2 (review A2-S1, fail closed): a seed is stored as a write seed and promoted only
    after its window closed cleanly with no write. When the crawl stops between the
    two (``_take_query_navs`` raises once), the seed stays a page that is never a
    point."""
    from fuzzlab.tools.spider import LocalSpider
    chromium_or_skip(monkeypatch)
    lab = TrackSpa()
    try:
        sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=10000)
        original, fired = sp._take_query_navs, []

        def take(depth):
            row = sp.storage.cursor.execute(
                "SELECT source FROM discovered_pages ORDER BY rowid DESC LIMIT 1").fetchone()
            if not fired and row and row[0] in (spa.SEED_SOURCE, spa.WRITE_SEED_SOURCE):
                fired.append(1)
                raise RuntimeError("injected")
            return original(depth)
        sp._take_query_navs = take
        with pytest.raises(RuntimeError, match="injected"):
            sp.crawl()
    finally:
        lab.close()
    sources = dict(db_rows(str(tmp_path / "s.db"), "SELECT url, source FROM discovered_pages"))
    assert sources[lab.base + "#/track-result?id=fuzzlab"] == spa.WRITE_SEED_SOURCE
    store, run, _c = _import(tmp_path / "s.db", tmp_path / "u.db")
    with store:
        assert not any(n == "id" for _u, n, _l in _params(store, run))


def _session_query_crawl(monkeypatch, tmp_path, raise_with):
    """The ``SessionQuerySpa`` crawl with the first client-side session check raising
    ``raise_with``; records the page's URL at each window's after-step."""
    from tests._spa_query_fixture import SessionQuerySpa
    from tests.test_forms_phase4 import _LsManager

    from fuzzlab.tools.spider import LocalSpider
    chromium_or_skip(monkeypatch)
    real, calls, seen = LocalSpider._client_session_intact, [], []

    def check(self):
        calls.append(1)
        if len(calls) == 1:
            raise raise_with("injected")
        return real(self)
    after = LocalSpider._after_query_window

    def spy(self, win, url, visited=True):
        seen.append(self._page.url)
        return after(self, win, url, visited)
    monkeypatch.setattr(LocalSpider, "_client_session_intact", check)
    monkeypatch.setattr(LocalSpider, "_after_query_window", spy)
    lab = SessionQuerySpa()
    try:
        manager = _LsManager(lab.base)
        sp = _crawl(lab, tmp_path / "s.db", session_manager=manager, identity="user")
    finally:
        lab.close()
    return lab, sp, seen


def test_a_session_check_that_raises_is_a_loss(monkeypatch, tmp_path):
    """U3 (review B2-M2): the first check (``calm``'s seed) raises a Playwright error:
    that is a loss, never a pass -- query loads stop (``fade`` and ``after1`` are
    queued and refused, never loaded) and the window still left for ``about:blank``."""
    from fuzzlab.tools.spider import PlaywrightError
    lab, sp, seen = _session_query_crawl(monkeypatch, tmp_path, PlaywrightError)
    gets = [r[1] for r in lab.seen("GET", "/rest/marker/")]
    assert "/rest/marker/calm-query" in gets
    assert "/rest/marker/fade-query" not in gets and "/rest/marker/after1-query" not in gets
    assert sp.spa_counts["spa_query_session_losses"] == 1
    assert sp.spa_query_stopped and "the session check failed" in sp.spa_query_stopped
    assert sp.spa_query_refused.get("session lost") == 2       # queued, then refused
    assert seen[0] == "about:blank"


def test_any_failure_of_the_session_check_is_a_loss_and_the_crawl_finishes(
        monkeypatch, tmp_path):
    """U3: a ``RuntimeError`` from the check is kept as a loss; the page still reaches
    ``about:blank`` and the crawl finishes with its counts stored."""
    _lab, sp, seen = _session_query_crawl(monkeypatch, tmp_path, RuntimeError)
    assert seen[0] == "about:blank"
    assert sp.spa_query_stopped and "RuntimeError" in sp.spa_query_stopped
    stats = dict(db_rows(str(tmp_path / "s.db"), "SELECT name, value FROM crawl_stats"))
    assert stats["spa_query_stopped"] == 1 and stats["spa_query_session_losses"] == 1


class _CookieState:
    cookies = {"sid": "S7d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a"}
    headers: dict = {}
    secure_only = False
    browser_state = None


class _CookieManager:
    def __init__(self):
        self.verified = 0

    def ensure(self, host, identity, base_url, operator=False):
        return _CookieState()

    def verify_live(self, host, identity, base_url):
        self.verified += 1
        return True


def test_a_slow_response_that_expires_the_session_cookie_is_a_loss(monkeypatch, tmp_path):
    """U4: the ``chill`` seed's slow GET answers ``Set-Cookie: sid=; Max-Age=0``; the
    session check sees the cleared cookie, query loads stop (``after2``'s seed is
    refused) and the session is re-adopted. End to end, it passes through either check
    -- the one before the page leaves or the re-check after the quiet period, depending
    on when the answer lands (Y4); the re-check alone is pinned by
    `test_a_cookie_cleared_while_the_page_leaves_is_a_loss`."""
    from tests._spa_query_fixture import SessionCookieSpa
    chromium_or_skip(monkeypatch)
    lab = SessionCookieSpa()
    try:
        sp = _crawl(lab, tmp_path / "s.db", session_manager=_CookieManager(),
                    identity="user")
    finally:
        lab.close()
    gets = [r[1] for r in lab.seen("GET", "/rest/marker/")]
    assert "/rest/marker/chill-query" in gets and "/rest/marker/after2-query" not in gets
    assert sp.spa_counts["spa_query_session_losses"] == 1
    assert sp.spa_query_stopped and "cookie 'sid'" in sp.spa_query_stopped


# =====================================================================================
# Merge with origin-scoped sessions (M1-M8, CC-CRAWL-0027 merge amendment)
# =====================================================================================
def test_a_withheld_url_while_a_probe_is_open_is_that_probes_blocked_evidence(
        tmp_path, caplog):
    """M1 (review B2-S3a, B4): an other-origin URL withheld while a probe is open
    carries its markers: it goes to that probe's blocked set only, never to
    ``skipped_other_origin``, the withheld targets or the log; outside a probe it is
    recorded as before."""
    import logging
    caplog.set_level(logging.INFO)
    sp = _requests_spider(tmp_path)
    try:
        marked = "http://127.0.0.1:8/x?t=fzqaaabcdefgh"
        sp._probe = {"blocked": set()}
        sp._note_session_withheld(marked, "document", marked)
        assert sp._probe["blocked"] == {marked}
        assert sp.skipped_other_origin == {} and not sp._withheld_targets
        assert "fzq" not in caplog.text
        assert sp.session_out_of_origin == 1
        sp._probe = None
        sp._note_session_withheld("http://127.0.0.1:8/land", "document")
        assert list(sp.skipped_other_origin) == ["http://127.0.0.1:8/land"]
    finally:
        sp.storage.close()


def test_a_probe_route_on_another_origin_is_never_minted_nor_loaded(monkeypatch, tmp_path):
    """M2 (review B2-S3b): the origin check runs on the probe's route before its
    markers are minted: the route is recorded under its own URL, no marker exists.
    (127.0.0.2 is host-scoped: its other ports are in scope, another origin.)"""
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider("http://127.0.0.2:9/", db_name=str(tmp_path / "s.db"),
                     engine="requests")
    other = "http://127.0.0.2:8/#/r"
    planned = [[(other, 1, spa.PROBE_SOURCE)]]
    minted = []
    sp._query_on = True
    sp._cookie_scope = lambda u: u.startswith("http://127.0.0.2:9/")
    assert sp._other_origin(other)
    monkeypatch.setattr(sp, "_plan_probes", lambda: planned.pop() if planned else [])
    monkeypatch.setattr(sp, "_mint_probe", lambda url: minted.append(url))
    monkeypatch.setattr(sp, "_fetch_static", lambda url: (_ for _ in ()).throw(
        OSError("no lab")))
    sp.crawl()
    assert minted == []
    assert list(sp.skipped_other_origin) == [other]


def _probe_spy(monkeypatch):
    """Every probe the crawl minted (the dicts themselves: their ``blocked`` sets fill
    as the loads run)."""
    from fuzzlab.tools.spider import LocalSpider
    seen = []
    real = LocalSpider._mint_probe

    def spy(self, route_url):
        probe = real(self, route_url)
        if probe is not None:
            seen.append(probe)
        return probe
    monkeypatch.setattr(LocalSpider, "_mint_probe", spy)
    return seen


def test_an_authenticated_query_load_that_goes_to_another_origin_hands_it_nothing(
        monkeypatch, tmp_path, caplog):
    """M3 + M5 (review B2-S3c, B-M1, B4), real Chromium, a cookie session on
    127.0.0.2:A, B on another port of 127.0.0.2. ``/goaway`` redirects to B, and its
    ``x`` seed with it: inside the seed's window the landing navigation is refused by
    the window (before the origin rule is asked), so the load fails and the seed stays a
    write seed, never a point; the landing is queued and then skipped as another origin
    (P3: window-refused, not withheld). ``/browse``'s probe opens a WebSocket to B and
    sends ``location.href`` there, each with this load's marker: B receives nothing, no
    row or seed comes of it, both URLs are that probe's blocked evidence, and no marker
    reaches ``skipped_other_origin`` or the log."""
    import logging

    from fuzzlab.tools.spider import LocalSpider
    from tests.test_session_origin_scope import _App, _mgr
    chromium_or_skip(monkeypatch)
    caplog.set_level(logging.INFO)
    b = _App("127.0.0.2")
    a = _App("127.0.0.2")
    shell = (b"<!doctype html><html><head><title>a</title><base href='/'>"
             b"<script src='/app.js'></script></head><body><p>shell</p></body></html>")
    script = ("function declare() { return new VueRouter({mode: 'history', routes: [\n"
              "  { path: '/goaway', component: G },\n"
              "  { path: '/browse', component: Br },\n]}); }\n"
              "class Nav{go(t){this.router.navigate([`/goaway`],{queryParams:{x:t}})}}\n"
              "function read(){ return this.route.snapshot.queryParams.term; }\n"
              "const m = /[?&]term=([^&]*)/.exec(location.search);\n"
              f"if (m) new WebSocket('ws://127.0.0.2:{b.port}/ws?t=' + m[1]);\n"
              f"if (m) addEventListener('load', () => setTimeout(() =>\n"
              f"  location.href = '{b.base}x?t=' + m[1], 50));\n")
    a.pages["/"] = a.pages["/browse"] = (200, shell, [])
    a.pages["/app.js"] = (200, script.encode(), [])
    a.redirects["/goaway"] = b.base + "land"
    seen = _probe_spy(monkeypatch)
    try:
        sp = LocalSpider(a.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=8000, session_manager=_mgr(
                             host="127.0.0.2"), identity="user")
        run_crawl(sp)
    finally:
        a.close()
        b.close()
    db = str(tmp_path / "s.db")
    assert b.requests == []                                  # nothing at B, no cookie
    # M3: the seed went to B: withheld, filed as a write seed
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert sources[a.base + "goaway?x=fuzzlab"] == spa.WRITE_SEED_SOURCE
    # M5: the probe of /browse sent its document to B: blocked evidence of that probe
    browse = [p for p in seen if p["route_url"] == a.base + "browse"]
    assert len(browse) == 1
    assert [u for u in browse[0]["blocked"] if u.startswith(b.base + "x?t=fzq")]
    # P3 (review B-S1): the socket to B with the marker: never connected, that probe's
    assert [u for u in browse[0]["blocked"]
            if u.startswith(f"ws://127.0.0.2:{b.port}/ws?t=fzq")]
    assert sp.spa_counts["spa_query_probe_loads"] >= 1
    assert sp.spa_counts["spa_query_kept"] == 0
    assert not [u for u in sources if "term=" in u]          # nothing queued
    assert "fzq" not in db_text(db)                          # no row
    assert not [u for u in sp.skipped_other_origin if "fzq" in u]
    assert b.base + "land" in sp.skipped_other_origin        # the seed's, no marker
    assert "fzq" not in caplog.text


def test_a_seeds_leave_reads_the_page_only_when_its_load_committed(tmp_path):
    """M6 (BUG-0136 review B-S3), P4 (B-N1): a seed whose load never committed (the page
    still shows an earlier document, or its goto never returned) queues nothing from
    ``page.url``; one that committed queues its same-document navigation."""
    sp = _requests_spider(tmp_path)
    try:
        seed = "http://127.0.0.1:9/#/x?a=fuzzlab"
        sp._doc_url = "http://127.0.0.1:9/#/earlier"            # this load's never came
        page = _FakePage("http://127.0.0.1:9/#/earlier")
        with sp._window(page, None, seed, query=spa.SEED_SOURCE) as win:
            pass
        assert win["navs"] == []
        # P4 (review B-N1): this load's own navigation, but it never committed
        sp._doc_url, sp._load_committed = seed, False
        page = _FakePage("http://127.0.0.1:9/#/moved")
        with sp._window(page, None, seed, query=spa.SEED_SOURCE) as win:
            pass
        assert win["navs"] == []
        sp._load_committed = True                                # committed, then moved
        page = _FakePage("http://127.0.0.1:9/#/moved")
        with sp._window(page, None, seed, query=spa.SEED_SOURCE) as win:
            pass
        assert win["navs"] == ["http://127.0.0.1:9/#/moved"]
    finally:
        sp.storage.close()


def test_a_failed_seed_load_checks_the_cookies_and_the_server_not_local_storage(tmp_path):
    """M7 (D54 B): after a failed seed load the page is ``about:blank`` (X1), which has
    no localStorage of the app: the window's check is the cookie half and the server's
    verdict, never the client-side check."""
    sp, ctx, manager = _session_spider(tmp_path, live=True)
    try:
        def no_client_check():
            raise AssertionError("the localStorage half ran on about:blank")
        sp._client_session_intact = no_client_check
        seed = "http://127.0.0.1:9/goaway?x=fuzzlab"
        sp._doc_url = seed
        with sp._window(_FakePage("about:blank"), ctx, seed,
                        query=spa.SEED_SOURCE) as win:
            pass
        assert win["session"] == (True, None) and manager.verified == 1
        ctx.jar = []                                             # and a lost cookie is a loss
        with sp._window(_FakePage("about:blank"), ctx, seed,
                        query=spa.SEED_SOURCE) as win:
            pass
        assert win["session"][0] is False
    finally:
        sp.storage.close()


def test_a_query_loads_request_in_flight_is_tracked_until_it_ends(tmp_path):
    """M8 (review A4-N1): a query load's XHR is in flight from its request until it
    finishes or fails; outside a query window nothing is tracked."""
    sp = _requests_spider(tmp_path)
    try:
        req = type("R", (), {"url": "http://127.0.0.1:9/rest/late", "resource_type": "xhr",
                             "method": "GET", "is_navigation_request": lambda s: False,
                             "failure": None})()
        sp._win = {"query": spa.SEED_SOURCE, "aborted": 0}
        sp._on_request(req)
        sp._on_request(req)
        assert sp._win["inflight"] == {req.url: 2}
        sp._on_request_finished(req)
        sp._on_request_failed(req)
        assert sp._win["inflight"] == {}
        sp._win = {"query": None, "aborted": 0}
        sp._on_request(req)
        assert "inflight" not in sp._win
    finally:
        sp.storage.close()


def _window_spy(monkeypatch):
    from fuzzlab.tools.spider import LocalSpider
    seen = []
    real = LocalSpider._after_query_window

    def spy(self, win, url, visited=True):
        seen.append({"url": url, "writes": win.get("writes", 0),
                     "blocked": set(win.get("blocked", ())), "visited": visited,
                     "xhr": list(self._xhr_urls), "session": win.get("session"),
                     "baseline": set(win.get("baseline", ()))})
        return real(self, win, url, visited)
    monkeypatch.setattr(LocalSpider, "_after_query_window", spy)
    return seen


def test_a_seed_whose_own_redirect_is_refused_fails_and_the_crawl_goes_on(
        monkeypatch, tmp_path):
    """M4, M7, M8, real Chromium, an authenticated crawl whose session is in
    localStorage. ``/goaway?x=`` redirects to a transaction GET its window refuses:
    the seed's load fails, is never re-sent as a static request and stays a write
    seed (M4); the page is then ``about:blank``, so the session check reads the cookies
    and the server, no loss, and the next seed still loads (M7). Each seed load starts
    from a fresh document, so the previous page's interval POSTs are never its write
    nor its XHR (M7). ``/late1?z=``'s slow GET is still in flight when the load is
    read: never queued, never fetched again (M8). P2 (review B-S2): the refused hop's
    transaction GET is a blocked write, never queued, never requested. P1(b), history
    mode: every load of the shell POSTs to ``/socket.io/`` and pings a WebSocket; in a
    seed's window (a full load) both are blocked, but the bare route's own load made the
    same writes, so they are its baseline and the seed is promoted."""
    from fuzzlab.tools.spider import LocalSpider
    from tests._spa_query_fixture import RedirectSeedSpa
    from tests.test_forms_phase4 import _LsManager
    chromium_or_skip(monkeypatch)
    seen = _window_spy(monkeypatch)
    lab = RedirectSeedSpa()
    try:
        manager = _LsManager(lab.base)
        sp = LocalSpider(lab.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=3000, session_manager=manager,
                         identity="user")
        run_crawl(sp)
        requests = list(lab.requests)
    finally:
        lab.close()
    db, base = str(tmp_path / "s.db"), lab.base
    gets = [r[1] for r in requests if r[0] == "GET"]
    # M4: one load of the seed, in its window; never a static re-send
    assert gets.count("/goaway?x=fuzzlab") == 1
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert sources[base + "goaway?x=fuzzlab"] == spa.WRITE_SEED_SOURCE
    # M7: no loss, the next seeds loaded and were promoted
    assert sp.spa_counts["spa_query_session_losses"] == 0 and not sp.spa_query_stopped
    assert "/rest/marker/_next1-query" in gets
    assert sources[base + "next1?y=fuzzlab"] == spa.SEED_SOURCE
    store, run, _counts = _import(db, tmp_path / "u.db")
    try:
        params = _params(store, run)
    finally:
        store.close()
    assert not [p for p in params if p[1] == "x"]
    assert ("/next1", "y", "query") in params
    # M7: no seed window saw the previous page's POSTs (a write) or requests (an XHR)
    windows = {w["url"]: w for w in seen}
    for url in (base + "goaway?x=fuzzlab", base + "next1?y=fuzzlab",
                base + "late1?z=fuzzlab"):
        # P2: the goaway seed's one write is its refused transaction hop
        assert windows[url]["writes"] == (1 if "goaway" in url else 0), url
        assert not [u for u in windows[url]["blocked"] | set(windows[url]["xhr"])
                    if "/api/tick" in u or u.endswith(("/rest/marker/_", "_goaway",
                                                       "_next1", "_late1"))], url
    assert windows[base + "goaway?x=fuzzlab"]["visited"] is False
    # M8: the late GET was in flight when /late1's seed was read: one fetch only
    assert gets.count("/rest/late") == 1
    assert not [u for u in sources if "/rest/late" in u]
    # P2: the hop's word-refused target was never queued, never requested
    assert not [r for r in requests if r[1].startswith("/api/order/confirm")]
    assert not [u for u in sources if "/api/order/confirm" in u]
    # P1(b): the shell's writes were made on every load, blocked in each seed's window,
    # and matched the bare route's baseline. Under capture (FR-CRAWL-18/19) none is ever
    # sent: outside a window the socket.io POST is recorded as a transport and aborted
    assert not [r for r in requests if r[0] == "POST" and r[1].startswith("/socket.io/")]
    assert db_rows(db, "SELECT url FROM discovered_requests WHERE source = 'transport' "
                       "AND url LIKE '%/socket.io/%'")
    nxt = windows[base + "next1?y=fuzzlab"]
    assert {("POST", "/socket.io/"), ("WS", "/socket.io/")} <= nxt["baseline"]
    assert [u for u in nxt["blocked"] if "/socket.io/" in u]
    assert sp.spa_counts["spa_query_baseline_writes"] >= 1


def test_a_withheld_seed_is_a_write_seed_and_a_withheld_probe_records_nothing(
        monkeypatch, tmp_path):
    """M3 (review B2-S3c): a query load whose own document was withheld (another
    origin, FR-SESS-20) is visited and extracts nothing, as any page -- but a seed is
    filed as a write seed (never a point) and a probe records nothing. Driven through
    the crawl loop with a fake page: in a real crawl the query window refuses such a
    navigation first, so this branch is the fail-closed backstop."""
    from fuzzlab.tools.spider import SessionWithheld
    sp = _requests_spider(tmp_path)
    seed = "http://127.0.0.1:9/goaway?x=fuzzlab"
    route = "http://127.0.0.1:9/browse"
    planned = [[(route, 1, spa.PROBE_SOURCE)], [(seed, 1, spa.SEED_SOURCE)]]
    loads = []

    def withheld(url, fallback=True):
        loads.append((url, fallback))
        raise SessionWithheld(url)
    sp.engine, sp._query_on = "playwright", True
    sp._page, sp._context = _FakePage("about:blank"), _FakeCtx()
    sp._query_unpaired = {"term": None}
    monkeypatch.setattr(sp, "_start_browser", lambda: None)
    monkeypatch.setattr(sp, "_stop_browser", lambda: None)
    monkeypatch.setattr(sp, "_plan_probes", lambda: planned.pop() if planned else [])
    monkeypatch.setattr(sp, "_fetch_rendered", withheld)
    monkeypatch.setattr(sp, "_goto_and_parse", lambda url: withheld(url))
    sp.crawl()
    rows = dict(db_rows(str(tmp_path / "s.db"), "SELECT url, source FROM discovered_pages"))
    assert (seed, False) in loads                       # M4: a seed never falls back
    assert rows[seed] == spa.WRITE_SEED_SOURCE
    probes = [u for u, _f in loads if u.startswith(route + "?term=")]
    assert len(probes) == 1 and probes[0] not in rows   # the probe recorded nothing
    assert not [u for u in rows if "term=" in u]


# =====================================================================================
# Post-merge fixes (D57, P1-P4): the shell's own writes, refused hops, logs
# =====================================================================================
def test_a_shell_that_writes_on_every_load_still_gives_hash_points(query_crawl):
    """P1 (review B-M1), on `QuerySpa`, whose shell POSTs a socket.io polling handshake
    on every load and pings a WebSocket every 100 ms (Juice Shop's shape). (a) A hash
    seed's bare route is loaded fresh outside its window, so the shell's start-up POST
    is sent there and never blocked in the seed's window; the seed is the same-document
    hash change inside it. (b) The pings that land inside the window are blocked but
    match the bare route's own writes (its baseline), so ``#/track?id=`` is promoted and
    imported as a fragment point, while ``#/poster?msg=``'s query-caused POST is still
    a write."""
    lab, db, sp = query_crawl["lab"], query_crawl["db"], query_crawl["sp"]
    first = query_crawl["first_requests"]
    # under capture (FR-CRAWL-18/19) the shell's writes are made, recorded and never
    # sent: the start-up POST as a transport row, the pings as dropped messages
    assert not [r for r in first if r[0] == "POST" and r[1].startswith("/socket.io/")]
    assert db_rows(db, "SELECT url FROM discovered_requests WHERE source = 'transport' "
                       "AND url LIKE '%/socket.io/%'")
    assert ("3",) in db_rows(db, "SELECT head FROM ws_dropped")   # the shell pinged
    assert lab.ws_messages == []
    windows = {w["url"]: w for w in query_crawl["windows"]}
    track = windows[lab.base + "#/track?id=fuzzlab"]
    # (a): the start-up POST was made before the window, never blocked in it
    assert not [u for u in track["blocked"] if "/socket.io/" in u]
    assert track["writes"] == 0 and track["visited"]
    assert {("POST", "/socket.io/"), ("WS", "/socket.io/")} <= track["baseline"]
    # (b): pings inside the window matched the baseline (blocked, not a write)
    assert sp.spa_counts["spa_query_baseline_writes"] >= 1
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert sources[lab.base + "#/track?id=fuzzlab"] == spa.SEED_SOURCE
    assert ("/#/track", "id", "fragment") in _params(query_crawl["store"],
                                                     query_crawl["run"])
    # the autopost seed's form (its blocked write) is never stored (P1 follow-up)
    assert not db_rows(db, "SELECT action_url FROM discovered_forms "
                           "WHERE action_url LIKE '%/api/autopost%'")
    poster = windows[lab.base + "#/poster?msg=fuzzlab"]
    assert poster["writes"] >= 1
    assert sources[lab.base + "#/poster?msg=fuzzlab"] == spa.WRITE_SEED_SOURCE


def test_the_baseline_is_what_a_load_outside_a_window_would_have_written(tmp_path):
    """P1(b), unit: while a load outside any window records (`_recording`), a request
    the query window would count as a write, and a forwarded WebSocket message, join
    the load's writes; a GET navigation or a plain GET does not. In a query window a
    write matching the route's baseline is blocked but not counted; another is."""
    from fuzzlab.tools.spider import _route_key

    def req(method, url, navigation=False):
        return type("R", (), {"url": url, "method": method, "resource_type": "fetch",
                              "is_navigation_request": lambda s: navigation,
                              "post_data_buffer": None})()
    sp = _requests_spider(tmp_path)
    try:
        sp._recording, sp._load_writes = True, set()
        sp._on_request(req("POST", "http://127.0.0.1:9/socket.io/?EIO=4&t=1"))
        sp._on_request(req("GET", "http://127.0.0.1:9/api/order/confirm?x=1"))
        sp._on_request(req("GET", "http://127.0.0.1:9/rest/products"))
        sp._on_request(req("GET", "http://127.0.0.1:9/next", navigation=True))
        sp._note_ws_send("ws://127.0.0.1:9/socket.io/?EIO=4&transport=websocket")
        assert sp._load_writes == {("POST", "/socket.io/"), ("GET", "/api/order/confirm"),
                                   ("WS", "/socket.io/")}
        sp._recording = False
        sp._note_ws_send("ws://127.0.0.1:9/other")
        assert ("WS", "/other") not in sp._load_writes
        assert _route_key("http://h/#/track?id=1") == "http://h/#/track"
        assert _route_key("http://h/next1?y=1") == "http://h/next1"
        sp._write_baseline["http://h/#/track"] = {("POST", "/socket.io/"),
                                                  ("WS", "/socket.io/")}
        ctx = object()
        with sp._window(_FakePage("http://h/#/track?id=1"), ctx, "http://h/#/track?id=1",
                        query=spa.SEED_SOURCE) as win:
            sp._window_refusal("POST", "http://h/socket.io/?t=2", False, context=ctx)
            sp._note_ws_drop("ws://h/socket.io/?EIO=4&transport=websocket")
            assert not win.get("writes")
            sp._window_refusal("POST", "http://h/api/send", False, context=ctx)
            sp._note_ws_drop("ws://h/ws")
            assert win["writes"] == 2
        assert sp.spa_counts["spa_query_baseline_writes"] == 2
        assert "http://h/socket.io/?t=2" in win["blocked"]       # blocked all the same
    finally:
        sp.storage.close()


def test_the_websocket_forwarder_reports_each_forwarded_message():
    """P1(b): a page-to-server message forwarded outside the window is reported to
    ``on_send`` (the baseline); a held one only to ``on_drop``, with its text (B2). A
    failing ``on_send`` never breaks the forwarder (B3)."""
    from fuzzlab.tools.navguard import make_ws_handler
    from tests.test_forms_phase4 import _WS
    state, sent, dropped = {"on": False}, [], []
    handler = make_ws_handler(lambda u: True, hold=lambda: state["on"],
                              on_drop=lambda u, m: dropped.append((u, m)),
                              on_send=sent.append)
    ws = _WS("ws://h/socket.io/")
    handler(ws)
    ws.handler("2probe")
    state["on"] = True
    ws.handler('42["search","fuzzlab"]')
    assert sent == ["ws://h/socket.io/"]
    assert dropped == [("ws://h/socket.io/", '42["search","fuzzlab"]')]

    def boom(url):
        raise RuntimeError("hook failed")
    handler = make_ws_handler(lambda u: True, hold=lambda: False, on_send=boom)
    ws = _WS("ws://h/socket.io/")
    handler(ws)
    ws.handler("3")
    assert ws.server.sent == ["3"]                       # forwarded all the same


def test_the_guards_url_log_lines_never_carry_a_probe_marker(caplog):
    """P4 (review B-N2): the guard's log lines that name a URL path (a destructive or
    refused request, a failed fetch) are scrubbed of probe markers."""
    import logging

    from fuzzlab.tools.navguard import make_route_handler
    from tests.test_forms_phase4 import _Route
    caplog.set_level(logging.INFO)
    marker = spa.mint_markers(1)[0]
    handler = make_route_handler(in_scope=lambda u: True)
    route = _Route(f"http://h/logout/{marker}")
    handler(route)
    assert route.outcome == "abort"
    handler = make_route_handler(in_scope=lambda u: True,
                                 method_refusal=lambda m, u: "refused")
    handler(_Route(f"http://h/api/{marker}", method="POST"))
    assert "blocked destructive browser request" in caplog.text
    assert "blocked browser POST" in caplog.text
    assert spa.MARKER_PREFIX not in caplog.text


def test_a_seeds_forms_are_stored_only_when_it_is_promoted(tmp_path):
    """P1 follow-up: since a hash seed is a same-document change (P1(a)), ``#/autopost``'s
    query-rendered form survives its refused auto-submit in the DOM; a seed's forms are
    kept with its window and stored only if the seed is promoted -- a write seed's form
    (the very write its window blocked) is never stored, so never a point."""
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    sp = _requests_spider(tmp_path)
    try:
        html = "<form method='post' action='/api/autopost'><input name='v'></form>"
        form = BeautifulSoup(html, "html.parser").find("form")
        for url, writes in (("http://127.0.0.1:9/#/a?go2=fuzzlab", 1),
                            ("http://127.0.0.1:9/#/b?go2=fuzzlab", 0)):
            sp.storage.mark_visited(url, 200, 1, source=spa.WRITE_SEED_SOURCE)
            win = {"query": spa.SEED_SOURCE, "closed": True, "writes": writes,
                   "forms": [form_record(form, url)]}
            sp._after_query_window(win, url, True)
        rows = sp.storage.cursor.execute("SELECT page_url FROM discovered_forms").fetchall()
        assert rows == [("http://127.0.0.1:9/#/b?go2=fuzzlab",)]
    finally:
        sp.storage.close()


# =====================================================================================
# The write baseline's holes (D60, B1-B3)
# =====================================================================================
def test_the_baseline_never_takes_a_query_caused_write_and_a_query_value_always_counts(
        monkeypatch, tmp_path):
    """B1 + B2, real Chromium, `BaselineSpa`. B1 (review A-M1 = B-S2): the crawled links
    ``#/poster?msg=hi`` and ``#/search?q=foo`` POST to ``/api/send`` and ``/api/s``
    because of their query; only a bare route's load is its baseline, so neither is,
    and both seeds stay write seeds, never imported. B2 (A-S1 = B-S1): ``#/find?q=``
    POSTs ``{"q": "fuzzlab"}`` to the shell's own ``/api/events`` and ``#/talk?q=`` emits
    the filler on the shell's socket.io socket: both baseline endpoints, but carrying
    the seed's filler, so both are writes. ``#/calm?q=`` (the shell's writes only) is
    still promoted and imported as a fragment point."""
    from fuzzlab.tools.spider import LocalSpider
    from tests._spa_query_fixture import BaselineSpa
    chromium_or_skip(monkeypatch)
    seen = _window_spy(monkeypatch)
    lab = BaselineSpa()
    try:
        sp = LocalSpider(lab.base + "start", max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=10000)
        run_crawl(sp)
    finally:
        lab.close()
    db, base = str(tmp_path / "s.db"), lab.base
    pages = _pages(db)
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    # the query links were crawled first, outside any window: their POSTs were made,
    # recorded and aborted (FR-CRAWL-18), never sent
    assert pages.index(base + "#/poster?msg=hi") < pages.index(base + "#/poster?msg=fuzzlab")
    assert pages.index(base + "#/search?q=foo") < pages.index(base + "#/search?q=fuzzlab")
    assert lab.seen("POST", "/api/send") == [] and lab.seen("POST", "/api/s") == []
    captured = {u.rsplit("/", 2)[-2:][-1] for (u,) in db_rows(
        db, "SELECT url FROM discovered_requests WHERE source = 'captured-aborted'")}
    assert {"send", "s"} <= captured
    # B1: never a baseline
    assert ("POST", "/api/send") not in sp._write_baseline.get(base + "#/poster", set())
    assert ("POST", "/api/s") not in sp._write_baseline.get(base + "#/search", set())
    assert ("POST", "/api/events") in sp._write_baseline[base + "#/find"]
    assert ("WS", "/socket.io/") in sp._write_baseline[base + "#/talk"]
    windows = {w["url"]: w for w in seen}
    for seed in ("#/poster?msg=fuzzlab", "#/search?q=fuzzlab",      # B1
                 "#/find?q=fuzzlab", "#/talk?q=fuzzlab"):            # B2
        assert sources[base + seed] == spa.WRITE_SEED_SOURCE, seed
        assert windows[base + seed]["writes"] >= 1, seed
    assert sources[base + "#/calm?q=fuzzlab"] == spa.SEED_SOURCE
    assert sp.spa_counts["spa_query_baseline_writes"] >= 1
    store, run, counts = _import(db, tmp_path / "u.db")
    try:
        params = _params(store, run)
        examples = {(r["url"], r["name"]): r["example"] for r in store.conn.execute(
            "SELECT e.url, p.name, p.example FROM parameter p JOIN endpoint e "
            "ON e.id = p.endpoint_id WHERE p.run_id = ?", (run,))}
    finally:
        store.close()
    assert ("/#/calm", "q", "fragment") in params
    assert counts["write_seed_skipped"] >= 4                # the four seeds: pages only
    for route in ("find", "talk"):
        assert not [p for p in params if p[0] == f"/#/{route}"], route
    # the crawled links are points of their own (a stated residual: a crawled link
    # whose load writes is imported until FR-FUZZ-50's M6 window); never the seeds
    assert examples[("/#/poster", "msg")] == "hi"
    assert examples[("/#/search", "q")] == "foo"


def test_a_write_carrying_the_loads_query_value_counts_on_a_baseline_endpoint(tmp_path):
    """B2, unit: on a baseline endpoint, a write whose URL, body (seen by the ``request``
    event, before or after the window refused it) or WebSocket text carries the load's
    filler or markers counts; the shell's own does not."""
    sp = _requests_spider(tmp_path)

    def req(url, body=None):
        return type("R", (), {"url": url, "method": "POST", "resource_type": "fetch",
                              "is_navigation_request": lambda s: False,
                              "post_data_buffer": body})()
    try:
        sp._write_baseline["http://h/#/find"] = {("POST", "/api/events"),
                                                 ("WS", "/socket.io/")}
        ctx = object()
        with sp._window(_FakePage("http://h/#/find?q=fuzzlab"), ctx,
                        "http://h/#/find?q=fuzzlab", query=spa.SEED_SOURCE) as win:
            win["taint"] = frozenset({"fuzzlab"})
            # the shell's own: baseline, not counted
            sp._on_request(req("http://h/api/events", b'{"page":"load"}'))
            sp._window_refusal("POST", "http://h/api/events", False, context=ctx)
            sp._note_ws_drop("ws://h/socket.io/?EIO=4", "3")
            assert not win.get("writes")
            # request event first, then the refusal
            sp._on_request(req("http://h/api/events?a=1", b'{"q":"fuzzlab"}'))
            sp._window_refusal("POST", "http://h/api/events?a=1", False, context=ctx)
            assert win["writes"] == 1
            # the refusal first, then the request event
            sp._window_refusal("POST", "http://h/api/events?a=2", False, context=ctx)
            assert win["writes"] == 1
            sp._on_request(req("http://h/api/events?a=2", b'{"q":"fuzzlab"}'))
            assert win["writes"] == 2
            # in the URL (percent-encoded), and in a WebSocket message
            sp._window_refusal("POST", "http://h/api/events?x=%66uzzlab", False,
                               context=ctx)
            sp._note_ws_drop("ws://h/socket.io/?EIO=4", '42["search","fuzzlab"]')
            sp._note_ws_drop("ws://h/socket.io/?EIO=4", b'42["search","fuzzlab"]')
            assert win["writes"] == 5
    finally:
        sp.storage.close()


def test_only_a_bare_routes_load_is_its_baseline():
    """B1, unit: the predicate."""
    from fuzzlab.tools.spider import _is_bare_route
    assert _is_bare_route("http://h/#/poster") and _is_bare_route("http://h/next1")
    assert not _is_bare_route("http://h/#/poster?msg=hi")
    assert not _is_bare_route("http://h/next1?y=1")


# =====================================================================================
# The merge with BUG-0138 (guarded navigation): S3, reviewer A's N1
# =====================================================================================
def test_a_query_load_whose_bare_route_did_not_load_is_refused(monkeypatch, tmp_path):
    """S3 (BUG-0138 merge), real Chromium, `HeadNavSpa`: the shell's head script
    navigates to ``/logout.php`` on every load; the guard refuses it, so the bare
    route's load never completes. The ``#/track?id=`` seed is refused ("bare route did
    not load", counted) and its window never entered: no seed is promoted, none stored."""
    from tests._spa_query_fixture import HeadNavSpa
    chromium_or_skip(monkeypatch)
    seen = _window_spy(monkeypatch)
    lab = HeadNavSpa()
    try:
        from fuzzlab.tools.spider import LocalSpider
        sp = LocalSpider(lab.base + "#/home", max_depth=2, db_name=str(tmp_path / "s.db"),
                         engine="playwright", timeout_ms=10000)
        run_crawl(sp)
    finally:
        lab.close()
    db = str(tmp_path / "s.db")
    assert lab.seen("GET", "/logout.php") == []                 # the guard refused it
    assert sp.spa_counts["spa_query_pairs"] == 1                 # the seed was planned
    assert sp.spa_query_refused.get("bare route did not load", 0) >= 1
    sources = dict(db_rows(db, "SELECT url, source FROM discovered_pages"))
    assert not [u for u, s in sources.items()
                if s in (spa.SEED_SOURCE, spa.WRITE_SEED_SOURCE)]
    assert seen == []                                            # no window entered
    stats = dict(db_rows(db, "SELECT name, value FROM crawl_stats"))
    assert stats["spa_query_refused[bare route did not load]"] >= 1


class _ReadPage(_FakePage):
    """A page double `_goto_and_parse` can read."""

    def title(self):
        return "t"

    def content(self):
        return "<html><body><p>own</p></body></html>"

    def evaluate(self, script, *a):
        return "own" if "innerText" in script else None

    def eval_on_selector_all(self, sel, script):
        return []


@pytest.mark.parametrize("shows_own,committed", [(True, True), (False, False)])
def test_a_load_that_committed_but_did_not_complete_is_committed(
        monkeypatch, tmp_path, shows_own, committed):
    """Reviewer A N1 (BUG-0138 merge): `_load_committed` comes from the Navigation
    result -- a navigation that committed but whose load did not complete (superseded)
    is committed while the page still shows its own document, and not once another
    document replaced it."""
    from fuzzlab.tools import navguard
    sp = _requests_spider(tmp_path)
    url = "http://127.0.0.1:9/next1?y=fuzzlab"
    resp = type("Resp", (), {"status": 200, "headers": {"content-type": "text/html"}})()
    monkeypatch.setattr(navguard, "navigate", lambda page, u, **kw: navguard.Navigation(
        resp, False, True, 0.0, "<html><title>r</title><body>got</body></html>"))
    monkeypatch.setattr(navguard, "shows_own_document", lambda page, u, r: shows_own)
    try:
        sp._page = _ReadPage(url if shows_own else "http://127.0.0.1:9/other")
        sp._goto_recording(url)
        assert sp._load_committed is committed
        assert sp._rendered_ok is False                         # not reached
    finally:
        sp.storage.close()
