"""A query value that selects distinct pages is budgeted as its own route shape
(FR-CRAWL-673, FR-CORE-661, CC-CRAWL-0672).

The frontier's per-route-shape budget (FR-CRAWL-35) counts ``/index?page=a`` and
``/index?page=b`` as one shape, so a front controller's pages were refused past the
budget like calendar cells. Now the pages the crawl loaded decide: when two values of
one query name (all else equal) gave pages with different form structures
(`core.pathtemplate.form_structure`), that name is a router and each of its values is a
shape of its own; values that only vary data (one structure) stay folded. Measured on
Mutillidae (CC-CRAWL-0672); the sites here are invented loopback servers."""

from __future__ import annotations

import threading
from urllib.parse import parse_qsl, urlsplit

from fuzzlab.core.pathtemplate import form_structure, values_select_pages
from fuzzlab.tools import spa
from fuzzlab.tools import spider as sp
from tests.test_spider_frontier import _Site, _stats

FORM_A = "<form method=post><input name=title><button name=go>Go</button></form>"
FORM_B = "<form><input name=q><select name=sort></select></form>"


def test_form_structure_keeps_forms_and_ignores_data():
    a1 = form_structure(f"<p>record 1</p>{FORM_A}")
    a2 = form_structure(f"<p>record 2 has more text</p><b>x</b>{FORM_A}")
    b = form_structure(FORM_B)
    assert a1 == a2 != b
    assert form_structure("<p>no forms</p>") == frozenset()
    assert form_structure(None) is None and form_structure("") is None


def test_values_select_pages_needs_two_known_structures():
    a, b = form_structure(FORM_A), form_structure(FORM_B)
    assert values_select_pages({"x": a, "y": b})
    assert not values_select_pages({"x": a, "y": a, "z": a})
    assert not values_select_pages({"x": a, "y": None})       # unknown is no evidence


def test_route_shape_keeps_a_routers_value_only():
    url = "http://h/index.php?page=a&id=7"
    assert spa.route_shape(url) == spa.route_shape("http://h/index.php?page=b&id=8")
    kept = spa.route_shape(url, {"page"})
    assert kept != spa.route_shape("http://h/index.php?page=b&id=7", {"page"})
    assert kept == spa.route_shape("http://h/index.php?page=a&id=9", {"page"})


def _frontier(limit=2):
    lock = threading.Condition(threading.RLock())
    return sp._Frontier(lock, sp.FrontierLimits(max_route_variants=limit),
                        is_visited=lambda u: False)


def test_the_frontier_splits_a_shape_once_loaded_pages_show_distinct_structures():
    f = _frontier()
    urls = [f"http://h/i?page={v}" for v in "abcd"]
    f.extend([(u, 1, "link", None) for u in urls])
    assert f.report()["rejected"] == {"route_shape": 2}            # c and d refused
    f.observe(urls[0], form_structure(FORM_A))
    f.observe(urls[1], form_structure(FORM_B))
    assert f.report()["routers"] == 1
    f.extend([(urls[2], 1, "link", None), (urls[3], 1, "link", None)])   # found again
    assert f.report()["rejected"] == {"route_shape": 2}            # both admitted now


def test_data_values_stay_folded_under_the_budget():
    f = _frontier()
    urls = [f"http://h/item?name={v}" for v in "abcd"]
    f.extend([(u, 1, "link", None) for u in urls[:2]])
    for u in urls[:2]:
        f.observe(u, form_structure(FORM_A))                       # one structure
    f.extend([(u, 1, "link", None) for u in urls[2:]])
    assert f.report()["routers"] == 0
    assert f.report()["rejected"] == {"route_shape": 2}


def test_unknown_pages_and_other_pairs_never_make_a_router():
    f = _frontier()
    f.observe("http://h/i?page=a", None)
    f.observe("http://h/i?page=b", form_structure(FORM_A))
    # same name, another value of a second name: not "all else equal"
    f.observe("http://h/i?page=c&lang=en", form_structure(FORM_B))
    assert f.report()["routers"] == 0


def test_a_crawl_reaches_every_routed_page_past_the_budget(tmp_path):
    """Real static-engine crawl: a front controller whose home links 6 routed pages,
    each with its own form; the route budget is 2. Every routed page is loaded."""
    forms = {v: f"<form><input name=f_{v}></form>" for v in "abcdef"}

    def index(h, n):
        page = dict(parse_qsl(urlsplit(h.path).query)).get("page", "home")
        links = "".join(f"<a href='/index?page={v}'>{v}</a>" for v in forms)
        return 200, f"<html><body>{forms.get(page, '')}{links}</body></html>", {}

    site = _Site({"/": lambda h, n: (200, "<a href='/index?page=home'>h</a>", {}),
                  "/index": index})
    db = str(tmp_path / "s.db")
    try:
        sp.LocalSpider(site.base, max_depth=3, db_name=db, engine="requests",
                       limits=sp.FrontierLimits(max_route_variants=2)).crawl()
        loaded = {dict(parse_qsl(urlsplit(h).query)).get("page") for h in site.hits
                  if h.startswith("/index")}
    finally:
        site.close()
    assert set(forms) <= loaded, loaded
    assert _stats(db)["frontier_routers"] >= 1


def test_a_crawl_keeps_folding_data_values(tmp_path):
    """The confusable alternative: ``/item?name=X`` pages share one form; the budget
    still bounds them."""
    def item(h, n):
        links = "".join(f"<a href='/item?name=n{k}'>x</a>" for k in range(10))
        return 200, f"<html><body>{FORM_A}{links}</body></html>", {}

    site = _Site({"/": lambda h, n: (200, "<a href='/item?name=start'>i</a>", {}),
                  "/item": item})
    db = str(tmp_path / "s.db")
    try:
        sp.LocalSpider(site.base, max_depth=3, db_name=db, engine="requests",
                       limits=sp.FrontierLimits(max_route_variants=2)).crawl()
    finally:
        site.close()
    assert site.gets("/item") <= 2
    assert _stats(db).get("frontier_routers", 0) == 0
