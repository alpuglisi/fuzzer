"""The site map page in a real browser (CC-UI-0500/0502, FR-UI-503/505; PA-0065).

TestClient never runs `sitetree.js`, so the treeview, the panes, the filters, the
polling refresh and the text-only rendering are verified here in real Chromium against a
seeded store, with zero page errors, console errors and CSP violations. Skips only when
the browser cannot run; `FUZZLAB_REQUIRE_BROWSER=1` turns that into a failure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests._browser import Server, free_port, launch_browser_or_skip, require_modules

require_modules()
from playwright.sync_api import expect, sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web import sitetree  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

ORIGIN = "http://127.0.0.1:8080"
XSS = '<img src=x onerror="window.__xss=1">'
STATIC = Path(__file__).resolve().parents[1] / "fuzzlab" / "web" / "static" / "js"
_CSP_COLLECTOR = """
window.__cspViolations = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`);
});
"""


def _seed(path) -> dict:
    with Store(path) as s:
        c = s.conn
        a = s.start_run("auto", "h")
        c.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (a, ORIGIN))
        b = s.start_run(f"crawler{XSS}", "h")                 # no target: its own host
        for url, m in (("/", "GET"), ("/#/search", "GET"), ("/shop/item.php", "GET"),
                       ("/shop/cart.php", "POST")):
            c.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?,?,?)",
                      (a, url, m))
        ep = c.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?,?, 'GET')",
                       (a, f"/x/{XSS}")).lastrowid
        c.execute("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                  "VALUES (?,?,?, 'query')", (a, ep, f"p{XSS}"))
        c.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, '/crawl/only', "
                  "'GET')", (b,))
        c.executemany("INSERT INTO endpoint (run_id, url, method) VALUES (?,?, 'GET')",
                      [(a, f"/wide/w{i:03d}") for i in range(250)])     # > one page

        def ev(path, param, cat, loc="query"):
            return json.dumps({"rule_id": "R", "category": cat, "url": ORIGIN + path,
                               "param": param, "method": "GET", "location": loc})
        c.execute("INSERT INTO candidate (run_id, evidence, oracle_status) VALUES "
                  "(?,?, 'inconclusive')", (a, ev("/#/search", "q", "xss", "fragment")))
        c.execute("INSERT INTO candidate (run_id, evidence, oracle_status) VALUES "
                  "(?,?, 'checked')", (a, ev("/shop/item.php", "id", "sql-injection")))
        c.execute("INSERT INTO candidate (run_id, evidence, oracle_status) VALUES "
                  "(?,?, 'checked')", (a, ev(f"/x/{XSS}", f"p{XSS}", f"cat{XSS}")))
        c.execute("INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                  "url, method, param) VALUES (?, 'xss-dom', 1, 'browser', '{}', "
                  "'/#/search', 'GET', 'q')", (a,))
        for _ in range(60):                                  # > one Issues page (50)
            c.execute("INSERT INTO finding (run_id, vuln_class, label, confidence, "
                      "evidence, url, method, param) VALUES (?, 'sqli', 1, "
                      "'error-signature', '{}', '/shop/item.php', 'GET', 'id')", (a,))
        c.execute("INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                  "url, method, param) VALUES (?,?, 1, ?, '{}', ?, 'GET', ?)",
                  (a, f"vc{XSS}", f"mech{XSS}", f"/x/{XSS}", f"p{XSS}"))
        c.commit()
    return {"a": a, "b": b}


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    path = tmp_path_factory.mktemp("sitemap") / "s.db"
    runs = _seed(path)
    port = free_port()
    cfg = load_config(overrides={"store_path": str(path), "web_port": port,
                                 "sitetree_poll_ms": 400}, environ={})
    server = Server(create_app(cfg), port)
    server.start()
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            yield {"base": f"http://127.0.0.1:{port}", "browser": browser, "path": path,
                   **runs}
            browser.close()
    finally:
        server.stop()
        sitetree.child_cache.clear()


class Tab:
    def __init__(self, site):
        self.ctx = site["browser"].new_context()
        self.ctx.add_init_script(_CSP_COLLECTOR)
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(15000)
        self.errors = []
        self.page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        self.page.on("console", lambda m: m.type == "error"
                     and self.errors.append(f"console: {m.text}"))
        self.page.goto(site["base"] + "/sitetree", wait_until="load")
        self.page.wait_for_selector('#sitetree-root[data-ready="1"] [role="treeitem"]')

    def item(self, label: str):
        return self.page.locator('li[role="treeitem"]', has=self.page.locator(
            ":scope > .st-row > .st-label", has_text=re.compile("^" + re.escape(label) + "$")))

    def open(self, *labels):
        for lab in labels:
            it = self.item(lab).first
            if it.get_attribute("aria-expanded") == "false":
                it.locator(":scope > .st-row .st-label").click()
                expect(it).to_have_attribute("aria-expanded", "true")
                expect(it.locator(":scope > ul > li").first).to_be_attached()
        return self.item(labels[-1]).first

    def problems(self):
        return self.errors + [f"csp: {v}" for v in
                              self.page.evaluate("window.__cspViolations || []")]

    def close(self):
        self.ctx.close()


@pytest.fixture
def tab(site):
    t = Tab(site)
    yield t
    t.close()


def test_tree_renders_hosts_routes_and_badges(tab, site):
    page = tab.page
    tops = page.locator('#st-tree > li[role="treeitem"] > .st-row .st-label').all_inner_texts()
    assert tops[0] == ORIGIN and tops[1].startswith(f"run #{site['b']} · crawler")
    tab.open(ORIGIN, "/")
    route = tab.item("#/search").first
    assert route.locator(":scope > .st-row .st-badge").inner_text() == "route"
    tab.open("#/search", "GET /#/search")
    param = tab.item("q · fragment").first
    assert "client-side" in param.locator(":scope > .st-row").inner_text()
    assert param.locator(":scope > .st-row .st-dot.sev-high").count() == 1
    assert "worst severity high" in param.locator(":scope > .st-row").inner_text()
    assert tab.problems() == []


def test_keyboard_navigation_follows_the_treeview_pattern(tab):
    page = tab.page
    first = tab.item(ORIGIN).first
    first.focus()
    page.keyboard.press("ArrowRight")                       # expand
    expect(first).to_have_attribute("aria-expanded", "true")
    page.wait_for_selector('#st-tree > li > ul [role="treeitem"]')
    page.keyboard.press("ArrowRight")                       # into the first child
    assert page.evaluate("document.activeElement.getAttribute('aria-level')") == "2"
    page.keyboard.press("ArrowLeft")                        # back to the parent
    assert page.evaluate("document.activeElement.querySelector('.st-label').textContent") \
        == ORIGIN
    page.keyboard.press("ArrowLeft")                        # collapse
    assert first.get_attribute("aria-expanded") == "false"
    page.keyboard.press("Enter")                            # select (+ toggle)
    assert first.get_attribute("aria-selected") == "true"
    assert tab.problems() == []


def test_selecting_a_node_fills_contents_and_issues_with_paging(tab):
    page = tab.page
    tab.open(ORIGIN, "shop")
    tab.item("shop").first.locator(":scope > .st-row .st-label").click()
    page.wait_for_selector("#st-children-table tbody tr")
    rows = page.locator("#st-children-table tbody tr td:first-child").all_inner_texts()
    assert rows == ["cart.php", "item.php"]
    page.wait_for_selector("#st-issues-table tbody tr")
    assert page.locator("#st-issues-table tbody tr").count() == 50
    hrefs = page.locator("#st-issues-table tbody a").evaluate_all(
        "els => els.map(e => e.getAttribute('href'))")
    assert all(re.fullmatch(r"/findings/\d+", h) for h in hrefs)
    page.click("#st-issues-more")
    expect(page.locator("#st-issues-table tbody tr")).to_have_count(60)
    assert page.locator("#st-issues-more").is_hidden()
    assert "60 findings" in page.inner_text("#st-roll")
    assert tab.problems() == []


def test_a_findings_count_focuses_the_issues_pane(tab):
    page = tab.page
    tab.open(ORIGIN)
    tab.item("shop").first.locator(":scope > .st-row .st-count").click()
    page.wait_for_selector("#st-issues-table tbody tr")
    expect(page.locator("#st-issues")).to_be_focused()
    assert tab.problems() == []


def test_status_toggle_and_run_lens_filter_the_tree(tab, site):
    page = tab.page
    page.check('input[name="status"][value="inconclusive"]')
    expect(page.locator('#st-tree > li[role="treeitem"]')).to_have_count(1)
    tab.open(ORIGIN)
    page.wait_for_selector('#st-tree > li > ul [role="treeitem"]')
    kids = page.locator('#st-tree > li > ul > li[role="treeitem"] > .st-row .st-label')
    assert kids.all_inner_texts() == ["/"]
    page.uncheck('input[name="status"][value="inconclusive"]')
    page.select_option("#st-run", str(site["b"]))
    tops = page.locator('#st-tree > li[role="treeitem"] > .st-row .st-label')
    expect(tops).to_have_count(1)
    expect(tops.first).to_have_text(re.compile(r"^run #"))
    assert tab.problems() == []


def test_the_page_refreshes_when_the_store_changes(tab, site):
    page = tab.page
    tab.open(ORIGIN)
    page.wait_for_timeout(900)                  # the first poll has taken its baseline
    with Store(site["path"]) as s:
        s.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, "
                       "'/zz-new/page', 'GET')", (site["a"],))
        s.conn.commit()
    try:
        page.wait_for_selector('#st-tree [role="treeitem"] .st-label >> text="zz-new"',
                               timeout=10000)
        # expansion was kept across the refresh
        assert tab.item(ORIGIN).first.get_attribute("aria-expanded") == "true"
    finally:
        with Store(site["path"]) as s:
            s.conn.execute("DELETE FROM endpoint WHERE url='/zz-new/page'")
            s.conn.commit()
    assert tab.problems() == []


def test_markup_in_stored_values_renders_as_text_everywhere(tab, site):
    """Paths, parameter names, vuln classes, mechanisms, categories and tool names come
    from a live target or a plugin: each render site shows them as text (FR-UI-503)."""
    page = tab.page
    tab.open(ORIGIN)
    host = tab.item(ORIGIN).first
    x = tab.item("x").first
    x.locator(":scope > .st-row .st-label").click()      # selects and expands
    expect(x).to_have_attribute("aria-expanded", "true")
    page.wait_for_selector("#st-issues-table tbody tr")
    tab.open(XSS, f"GET /x/{XSS}", f"p{XSS} · query")
    tab.item(f"GET /x/{XSS}").first.locator(":scope > .st-row .st-label").click()
    page.wait_for_selector("#st-node-kv dd")
    page.click("#st-filters details#st-severity-box > summary")
    root_text = page.inner_text("#sitetree-root")
    for needle in (f"/x/{XSS}", f"p{XSS}", f"vc{XSS}", f"mech{XSS}"):
        assert needle in root_text, needle
    assert f"crawler{XSS}" in page.inner_text("#st-run") or \
        f"crawler{XSS}" in page.inner_text("#st-tree")
    assert page.evaluate("window.__xss") is None
    assert page.locator("#sitetree-root img").count() == 0
    assert host.count() == 1 and tab.problems() == []


_BANNED = re.compile(r"\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write"
                     r"|\beval\s*\(|new\s+Function\s*\(|\.html\s*\(|createContextualFragment"
                     r"|\bDOMParser\b|\bsrcdoc\b|setHTMLUnsafe|parseHTMLUnsafe")


def _page_scripts(template: str, read) -> set[str]:
    """Every script the page loads: base.html's, the page's own, and everything they
    import, transitively."""
    todo = {"shell.js", "prefs.js", *re.findall(r'src="/static/js/([\w.-]+)"', template)}
    seen: set[str] = set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo |= set(re.findall(r'from\s+"/static/js/([\w.-]+)"', read(name))) - seen
    return seen


def _offenders(names, read) -> list[str]:
    return [f"{n}: {m.group(0)}" for n in sorted(names) for m in _BANNED.finditer(read(n))]


def test_page_scripts_never_parse_html_strings():
    """The textContent-only claim, enforced in source for every script the page loads,
    imports followed transitively; proven on a synthetic offender (PA-0034(2))."""
    template = (Path(__file__).resolve().parents[1] / "fuzzlab" / "web" / "templates"
                / "sections" / "sitetree.html").read_text()
    names = _page_scripts(template, lambda n: (STATIC / n).read_text())
    assert {"sitetree.js", "shell.js", "prefs.js"} <= names
    assert _offenders(names, lambda n: (STATIC / n).read_text()) == []
    fake = {"page.js": 'import { x } from "/static/js/mid.js";',
            "mid.js": 'import { y } from "/static/js/deep.js";',
            "deep.js": "el.innerHTML = s; new DOMParser();",
            "shell.js": "", "prefs.js": ""}
    found = _page_scripts('<script src="/static/js/page.js">', fake.__getitem__)
    assert found == set(fake)
    assert _offenders(found, fake.__getitem__) == ["deep.js: innerHTML", "deep.js: DOMParser"]


def _wide(tab):
    tab.open(ORIGIN, "wide")
    group = tab.item("wide").first.locator(":scope > ul[role=group]")
    expect(group.locator(":scope > li[role=treeitem]")).to_have_count(200)
    return group


def test_show_more_loads_one_page_per_click_and_works_from_the_keyboard(tab):
    page = tab.page
    group = _wide(tab)
    btn = group.locator(":scope > li.st-more-item button")
    btn.focus()
    page.keyboard.press("Enter")                     # the button's own key, not the tree's
    expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
    assert tab.item("wide").first.get_attribute("aria-expanded") == "true"
    ids = group.locator(":scope > li[role=treeitem]").evaluate_all(
        "els => els.map(e => e.dataset.id)")
    assert len(ids) == len(set(ids)) == 250
    assert group.locator(":scope > li.st-more-item").count() == 0
    assert tab.problems() == []


def test_a_double_click_on_show_more_loads_the_page_once(tab):
    group = _wide(tab)
    group.locator(":scope > li.st-more-item button").dblclick()
    expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
    tab.page.wait_for_timeout(500)
    assert group.locator(":scope > li[role=treeitem]").count() == 250
    assert tab.problems() == []


def test_a_refresh_keeps_focus_selection_and_loaded_pages(tab, site):
    """Code review A2 (FR-UI-505): the store changing refreshes in place."""
    page = tab.page
    group = _wide(tab)
    group.locator(":scope > li.st-more-item button").click()
    expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
    late = tab.item("w240").first
    late.locator(":scope > .st-row .st-label").click()      # select + focus on page 2
    expect(late).to_be_focused()
    page.wait_for_timeout(900)                               # the poll has its baseline
    with Store(site["path"]) as s:
        s.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, "
                       "'/wide/w999', 'GET')", (site["a"],))
        s.conn.commit()
    try:
        expect(tab.item("w999").first).to_be_attached(timeout=10000)
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(251)
        expect(late).to_be_focused()
        assert late.get_attribute("aria-selected") == "true"
        assert tab.item("wide").first.get_attribute("aria-expanded") == "true"
    finally:
        with Store(site["path"]) as s:
            s.conn.execute("DELETE FROM endpoint WHERE url='/wide/w999'")
            s.conn.commit()
    assert tab.problems() == []


def test_show_more_from_the_keyboard_keeps_focus_in_the_tree(tab):
    page = tab.page
    group = _wide(tab)
    group.locator(":scope > li.st-more-item button").focus()
    page.keyboard.press("Enter")
    expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
    expect(group.locator(":scope > li[role=treeitem]").nth(200)).to_be_focused()
    assert tab.problems() == []


def test_a_truncated_endpoint_says_so_in_the_tree_and_the_contents(tab, monkeypatch):
    """Code review re-check (B-N3, PA-0065(3)): a partial endpoint list is shown as
    partial in the real page, never silently."""
    monkeypatch.setattr(sitetree, "GROUP_CAP", 0)          # the server runs in-process
    sitetree.child_cache.clear()
    try:
        page = tab.page
        tab.open(ORIGIN, "shop", "item.php")
        ep = tab.item("GET /shop/item.php").first
        ep.locator(":scope > .st-row .st-label").click()   # select + expand
        expect(ep.locator(":scope > ul > li.st-trunc-item")).to_be_visible()
        expect(page.locator("#st-node-truncated")).to_be_visible()
        assert tab.problems() == []
    finally:
        sitetree.child_cache.clear()


def test_a_refresh_that_overtakes_an_expand_still_fills_the_node(tab, site):
    """Code review re-check (A-N1): an expand in flight when a refresh starts is loaded
    by the refresh, never left expanded and empty."""
    page = tab.page
    held = []

    def hold_first_shop_load(route):
        if not held and "shop" in route.request.url:
            held.append(route)                              # answered after the refresh
        else:
            route.continue_()
    page.route("**/api/sitetree/children?*", hold_first_shop_load)
    tab.open(ORIGIN)
    page.wait_for_timeout(900)                              # the poll has its baseline
    shop = tab.item("shop").first
    shop.focus()
    page.keyboard.press("ArrowRight")                       # expand only: its load is held
    expect(shop).to_have_attribute("aria-expanded", "true")
    page.wait_for_timeout(300)
    assert held, "the expand's own load was not held"
    expect(shop.locator(":scope > ul > li[role=treeitem]")).to_have_count(0)
    with Store(site["path"]) as s:                          # a write: the next poll refreshes
        s.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, "
                       "'/zz-race', 'GET')", (site["a"],))
        s.conn.commit()
    try:
        expect(tab.item("zz-race").first).to_be_attached(timeout=10000)
        expect(shop.locator(":scope > ul > li[role=treeitem]")).to_have_count(2)
        assert held, "the expand's own load was not held"
        held[0].continue_()                                 # the stale answer arrives last
        page.wait_for_timeout(500)
        expect(shop.locator(":scope > ul > li[role=treeitem]")).to_have_count(2)
        assert shop.get_attribute("aria-expanded") == "true"
    finally:
        with Store(site["path"]) as s:
            s.conn.execute("DELETE FROM endpoint WHERE url='/zz-race'")
            s.conn.commit()
    assert tab.problems() == []


def test_an_expand_inside_a_refresh_loads_the_node_once(tab, site):
    """Code review R3-1: an expand made while a refresh is under way, and that refresh
    reaching the same still-empty node, share one load -- never two appended copies."""
    page = tab.page
    held = {"root": None, "wide": None}

    def hold(route):
        url = route.request.url
        if held["root"] is None and "node=" not in url and armed[0]:
            held["root"] = route                       # the refresh's root fetch
        elif held["wide"] is None and "wide" in url and armed[0]:
            held["wide"] = route                       # the expand's own fetch
        else:
            route.continue_()
    armed = [False]
    page.route("**/api/sitetree/children?*", hold)
    tab.open(ORIGIN)
    page.wait_for_timeout(900)                         # the poll has its baseline
    armed[0] = True
    with Store(site["path"]) as s:
        s.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, "
                       "'/zz-r31', 'GET')", (site["a"],))
        s.conn.commit()
    try:
        for _ in range(50):                            # until the next poll's refresh
            if held["root"] is not None:
                break
            page.wait_for_timeout(200)
        assert held["root"] is not None, "the refresh never started"
        wide = tab.item("wide").first
        wide.focus()
        page.keyboard.press("ArrowRight")              # expand during the refresh
        page.wait_for_timeout(300)
        assert held["wide"] is not None, "the expand's fetch was not held"
        held["root"].continue_()                       # the refresh reaches the node...
        page.wait_for_timeout(500)
        held["wide"].continue_()                       # ...then the expand's answer lands
        group = wide.locator(":scope > ul[role=group] > li[role=treeitem]")
        expect(group).to_have_count(200)
        page.wait_for_timeout(500)
        ids = group.evaluate_all("els => els.map(e => e.dataset.id)")
        assert len(ids) == len(set(ids)) == 200
    finally:
        with Store(site["path"]) as s:
            s.conn.execute("DELETE FROM endpoint WHERE url='/zz-r31'")
            s.conn.commit()
    assert tab.problems() == []
