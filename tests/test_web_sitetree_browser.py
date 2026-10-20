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
    _baseline(page)                             # the first poll has its baseline (D8)
    r0 = _count(page, "refreshes")
    with _Written(site, "/zz-new/page"):        # a writer in another process (D4)
        _reach(page, "refreshes", r0 + 1)
        expect(tab.item("zz-new").first).to_be_attached()
        # expansion was kept across the refresh
        assert tab.item(ORIGIN).first.get_attribute("aria-expanded") == "true"
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


@pytest.mark.parametrize("where", ["after", "before"])
def test_a_refresh_keeps_focus_selection_and_loaded_pages(tab, site, where):
    """Code review A2 (FR-UI-505): the store changing refreshes in place. The write
    sorts after the focused item, or before it (blocker 3): focus and selection stay on
    the same item, by identity, never on whatever now holds its position. Synchronised
    on the page's counters (it once failed waiting 10 s for /wide/w999: DRAFT §5.6)."""
    page = tab.page
    group = _wide(tab)
    group.locator(":scope > li.st-more-item button").click()
    expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
    late = tab.item("w240").first
    late.locator(":scope > .st-row .st-label").click()      # select + focus on page 2
    expect(late).to_be_focused()
    ident = late.get_attribute("data-id")
    _baseline(page)
    w = _refreshed_by_write(tab, site, "/wide/w999" if where == "after" else "/wide/w0005")
    try:
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(251)
        assert _focused_item(page) == [ident, "w240"]
        assert late.get_attribute("aria-selected") == "true"
        assert tab.item("wide").first.get_attribute("aria-expanded") == "true"
    finally:
        w.__exit__(None, None, None)
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
    _baseline(page)                                         # the poll has its baseline
    shop = tab.item("shop").first
    shop.focus()
    with page.expect_request(lambda r: "/api/sitetree/children" in r.url and "shop" in r.url):
        page.keyboard.press("ArrowRight")                   # expand only: its load is held
    expect(shop).to_have_attribute("aria-expanded", "true")
    assert _until(page, lambda: held), "the expand's own load was not held"
    expect(shop.locator(":scope > ul > li[role=treeitem]")).to_have_count(0)
    r0 = _count(page, "refreshes")
    with _Written(site, "/zz-race"):                        # the next poll refreshes
        _reach(page, "refreshes", r0 + 1)
        expect(tab.item("zz-race").first).to_be_attached()
        expect(shop.locator(":scope > ul > li[role=treeitem]")).to_have_count(2)
        loads = _count(page, "loads")
        held[0].continue_()                                 # the stale answer arrives last
        _reach(page, "loads", loads + 1)                    # ...and has been handled
        expect(shop.locator(":scope > ul > li[role=treeitem]")).to_have_count(2)
        assert shop.get_attribute("aria-expanded") == "true"
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
    _baseline(page)                                    # the poll has its baseline
    armed[0] = True
    r0 = _count(page, "refreshes")
    with page.expect_request(lambda r: "/api/sitetree/children" in r.url
                             and "node=" not in r.url, timeout=15000):
        w = _Written(site, "/zz-r31").__enter__()      # the next poll's refresh starts
    try:
        assert _until(page, lambda: held["root"] is not None), "the refresh never started"
        wide = tab.item("wide").first
        wide.focus()
        with page.expect_request(lambda r: "wide" in r.url):
            page.keyboard.press("ArrowRight")          # expand during the refresh
        assert _until(page, lambda: held["wide"] is not None), \
            "the expand's fetch was not held"
        loads = _count(page, "loads")
        held["root"].continue_()                       # the refresh reaches the node...
        _reach(page, "loads", loads + 1)
        held["wide"].continue_()                       # ...then the expand's answer lands
        group = wide.locator(":scope > ul[role=group] > li[role=treeitem]")
        expect(group).to_have_count(200)
        _reach(page, "refreshes", r0 + 1)              # the refresh is over
        ids = group.evaluate_all("els => els.map(e => e.dataset.id)")
        assert len(ids) == len(set(ids)) == 200
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


# --- a live refresh keeps the user's place (FR-UI-514, CC-UI-0068, BUG-0534) ------------
# Synchronisation is by the page's own counters (`#sitetree-root` data-baseline, -polls,
# -refreshes: D8), never by sleeping; every test asserts that its refresh happened.

def _count(page, name: str, root: str = "#sitetree-root") -> int:
    return page.eval_on_selector(root, f"r => parseInt(r.dataset.{name} || '0', 10)")


def _reach(page, name: str, n: int, root: str = "#sitetree-root", timeout=15000) -> None:
    page.wait_for_function(
        "([sel, k, n]) => parseInt(document.querySelector(sel).dataset[k] || '0', 10) >= n",
        arg=[root, name, n], timeout=timeout)


def _baseline(page, root: str = "#sitetree-root") -> None:
    """The page's poll has taken its baseline version (a write after this refreshes)."""
    page.wait_for_function("(sel) => document.querySelector(sel).dataset.baseline === '1'",
                           arg=root, timeout=15000)


def _xsql(site, sql: str, *params) -> None:
    """One commit by a writer in **another process** (D4: the web server runs in this
    test's process; a scan is another process). A plain connection: no run is added."""
    from tests._xproc import Writer
    with Writer(site["path"]) as w:
        w("open_plain")
        w("sql", sql, *params)
        w("close")


class _Written:
    """One endpoint written by another process, and undone by another process."""

    def __init__(self, site, url):
        self.site, self.url = site, url

    def __enter__(self):
        _xsql(self.site, "INSERT INTO endpoint (run_id, url, method) VALUES (?,?, 'GET')",
              self.site["a"], self.url)
        return self

    def __exit__(self, *exc):
        _xsql(self.site, "DELETE FROM endpoint WHERE url=?", self.url)


class _Finding:
    """One newer finding under /shop/item.php's `id` (it sorts first: newest first)."""

    def __init__(self, site):
        self.site = site

    def __enter__(self):
        _xsql(self.site, "INSERT INTO finding (run_id, vuln_class, label, confidence, "
              "evidence, url, method, param) VALUES (?, 'sqli', 1, 'zz-newest', '{}', "
              "'/shop/item.php', 'GET', 'id')", self.site["a"])
        return self

    def __exit__(self, *exc):
        _xsql(self.site, "DELETE FROM finding WHERE confidence='zz-newest'")


def _focused_item(page) -> list:
    """The focused tree item's identity: ``[data-id, label]``."""
    return page.evaluate("() => { const a = document.activeElement; return [a.dataset.id, "
                         "(a.querySelector(':scope > .st-row .st-label') || {}).textContent]; }")


def _refreshed_by_write(tab, site, url):
    """Write ``url`` (another process), wait for the page's next refresh to show it;
    returns the write, to be undone."""
    r0 = _count(tab.page, "refreshes")
    w = _Written(site, url).__enter__()
    try:
        _reach(tab.page, "refreshes", r0 + 1)
        expect(tab.item(url.rsplit("/", 1)[-1]).first).to_be_attached()
    except BaseException:
        w.__exit__(None, None, None)
        raise
    return w


@pytest.mark.parametrize("where", ["after", "before"])
def test_a_refresh_keeps_focus_on_show_more_and_enter_still_loads_the_page(tab, site, where):
    """E3 (p2): a refresh between focusing "Show more" and pressing Enter replaced the
    button; focus fell to <body> and Enter loaded nothing (200 of 250). The write sorts
    after the group, or before it among its siblings (blocker 3): the button keeps focus
    by identity, and the page's first item (w200) gets it, by identity."""
    page = tab.page
    group = _wide(tab)
    _baseline(page)
    group.locator(":scope > li.st-more-item button").focus()
    w = _refreshed_by_write(tab, site, "/zz-b1" if where == "after" else "/aa-b1")
    try:
        expect(group.locator(":scope > li.st-more-item button")).to_be_focused()
        page.keyboard.press("Enter")
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
        assert _focused_item(page)[1] == "w200"
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


def _until(page, cond, rounds: int = 400) -> bool:
    """Pump the page's events (a route handler runs only then) until ``cond()``; bounded
    by round trips, never by a sleep."""
    for _ in range(rounds):
        if cond():
            return True
        page.evaluate("0")
    return cond()


def _hold(page, want):
    """Hold the first /api/sitetree/children request ``want(url)`` picks; pass the rest."""
    held = []

    def route(r):
        if not held and want(r.request.url):
            held.append(r)
        else:
            r.continue_()
    page.route("**/api/sitetree/children?*", route)
    return held


@pytest.mark.parametrize("where", ["after", "before"])
def test_a_refresh_during_a_show_more_load_still_delivers_that_page(tab, site, where):
    """E4 (p3), one order: the user's page is in flight when a refresh starts. The
    refresh dropped it as stale: 200 items, focus on <body>. The write sorts after the
    group, or inside it before the page (blocker 3): the page's first item (w200) gets
    focus by identity."""
    page = tab.page
    group = _wide(tab)
    _baseline(page)
    held = _hold(page, lambda u: "wide" in u and "after=" in u)
    group.locator(":scope > li.st-more-item button").focus()
    with page.expect_request(lambda r: "wide" in r.url and "after=" in r.url):
        page.keyboard.press("Enter")                       # the user's page: held
    assert _until(page, lambda: held), "the user's page load was not held"
    w = _refreshed_by_write(tab, site, "/zz-b2" if where == "after" else "/wide/w0005")
    n = 250 if where == "after" else 251
    try:
        held[0].continue_()                                # the stale answer lands last
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(n)
        assert _focused_item(page)[1] == "w200"
        ids = group.locator(":scope > li[role=treeitem]").evaluate_all(
            "els => els.map(e => e.dataset.id)")
        assert len(ids) == len(set(ids)) == n
        assert group.locator(":scope > li.st-more-item").count() == 0
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


@pytest.mark.parametrize("where", ["after", "before"])
def test_show_more_pressed_while_a_refresh_loads_its_group_is_kept(tab, site, where):
    """E4, the other order (D6): the refresh's fetch of the group is in flight when the
    user presses "Show more"; the refresh must neither drop nor duplicate that page. The
    write sorts after the group or inside it before the page (blocker 3): focus stays on
    the page's first item (w200), by identity."""
    page = tab.page
    group = _wide(tab)
    _baseline(page)
    held = _hold(page, lambda u: "wide" in u and "after=" not in u)
    r0 = _count(page, "refreshes")
    url = "/zz-b2b" if where == "after" else "/wide/w0005"
    n = 250 if where == "after" else 251
    with page.expect_request(lambda r: "wide" in r.url and "after=" not in r.url,
                             timeout=15000):
        w = _Written(site, url).__enter__()                # the next poll refreshes
    try:
        assert _until(page, lambda: held), "the refresh's fetch of the group was not held"
        group.locator(":scope > li.st-more-item button").focus()
        page.keyboard.press("Enter")                       # the user's page passes
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(250)
        held[0].continue_()                                # the refresh's answer lands
        _reach(page, "refreshes", r0 + 1)
        expect(tab.item(url.rsplit("/", 1)[-1]).first).to_be_attached()
        items = group.locator(":scope > li[role=treeitem]")
        expect(items).to_have_count(n)
        ids = items.evaluate_all("els => els.map(e => e.dataset.id)")
        assert len(ids) == len(set(ids)) == n
        assert _focused_item(page)[1] == "w200"
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


def test_a_refresh_that_ends_a_groups_paging_keeps_focus_in_the_tree(tab, site):
    """E3: "Show more" is focused when a refresh finds the group fits one page (rows
    deleted); focus goes to the group's last item, never <body>."""
    page = tab.page
    group = _wide(tab)
    _baseline(page)
    group.locator(":scope > li.st-more-item button").focus()
    r0 = _count(page, "refreshes")
    _xsql(site, "DELETE FROM endpoint WHERE url BETWEEN '/wide/w190' AND '/wide/w249'")
    try:
        _reach(page, "refreshes", r0 + 1)
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(190)
        expect(group.locator(":scope > li.st-more-item")).to_have_count(0)
        assert _focused_item(page)[1] == "w189"            # the group's last item
    finally:
        _xsql(site, "WITH RECURSIVE n(i) AS (SELECT 190 UNION ALL SELECT i + 1 FROM n "
              "WHERE i < 249) INSERT INTO endpoint (run_id, url, method) "
              "SELECT ?, printf('/wide/w%03d', i), 'GET' FROM n", site["a"])
    assert tab.problems() == []


_ROW_FOCUS = """() => { const a = document.activeElement;
  return [a === window.__focused, a.tagName, a.getAttribute('href') || a.getAttribute('aria-label'),
          a.closest('li[role=treeitem]').dataset.id]; }"""


@pytest.mark.parametrize("where", ["after", "before"])
@pytest.mark.parametrize("control", ["findings count", "open link"])
def test_a_refresh_keeps_focus_on_a_control_inside_a_row(tab, site, control, where):
    """E5 (p4): a refresh rebuilt the row and dropped focus from its control to <body>.
    The focused control is updated in place: the same element keeps focus. The write
    sorts after the row, or before it (blocker 3: a sibling before "shop"; a newer
    finding, listed first, before the focused one): the same node, the same href or
    label, in the same item."""
    page = tab.page
    if control == "findings count":
        tab.open(ORIGIN)
        target = tab.item("shop").first.locator(":scope > .st-row .st-count")
    else:
        tab.open(ORIGIN, "shop", "item.php", "GET /shop/item.php", "id · query")
        target = tab.item("id · query").first.locator(
            ":scope > ul > li.st-finding > .st-row .st-open").first
    _baseline(page)
    findings = tab.item("id · query").first.locator(":scope > ul > li.st-finding")
    shown = findings.count()
    target.focus()
    page.evaluate("() => { window.__focused = document.activeElement; }")
    before = page.evaluate(_ROW_FOCUS)
    if where == "after":
        w = _refreshed_by_write(tab, site, "/zz-b4")
    elif control == "findings count":
        w = _refreshed_by_write(tab, site, "/aa-b4")
    else:
        r0 = _count(page, "refreshes")
        w = _Finding(site).__enter__()
        _reach(page, "refreshes", r0 + 1)
    try:
        if where == "before" and control == "open link":    # the newer finding is first
            expect(findings).to_have_count(shown + 1)
            assert findings.first.locator(".st-open").get_attribute("href") != before[2]
        after = page.evaluate(_ROW_FOCUS)
        assert after == before and after[0], (before, after)
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


def _issues_60(tab):
    page = tab.page
    tab.open(ORIGIN, "shop")
    tab.item("item.php").first.locator(":scope > .st-row .st-label").click()
    rows = page.locator("#st-issues-table tbody tr")
    expect(rows).to_have_count(50)
    return rows


@pytest.mark.parametrize("where", ["after", "before"])
def test_a_refresh_keeps_the_issues_pages_and_the_focused_finding(tab, site, where):
    """E5 (p5): a refresh re-rendered Issues from its first page (60 rows back to 50) and
    dropped the focused finding link to <body>. The write is an endpoint (no new row),
    or a newer finding, listed first, before the focused one (blocker 3): every row shown
    stays, and focus stays on the same finding, by its href."""
    page = tab.page
    rows = _issues_60(tab)
    page.click("#st-issues-more")
    expect(rows).to_have_count(60)
    _baseline(page)
    link = rows.nth(55).locator("a")
    key = link.get_attribute("href")
    link.focus()
    if where == "after":
        w = _refreshed_by_write(tab, site, "/zz-b5")
    else:
        r0 = _count(page, "refreshes")
        w = _Finding(site).__enter__()
        _reach(page, "refreshes", r0 + 1)
    try:
        expect(rows).to_have_count(60 if where == "after" else 61)
        expect(page.locator(f'#st-issues-table a[href="{key}"]')).to_be_focused()
        assert page.evaluate("() => document.activeElement.getAttribute('href')") == key
        if where == "before":                               # the newer one is first
            assert rows.nth(0).locator("a").get_attribute("href") != key
            assert rows.nth(56).locator("a").get_attribute("href") == key
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


def test_show_more_findings_pressed_while_a_refresh_loads_issues_is_kept(tab, site):
    """E5, the other order (D6): the refresh's Issues fetch is in flight when the user
    asks for the next page; the refresh must neither drop it (50) nor duplicate it."""
    page = tab.page
    rows = _issues_60(tab)
    _baseline(page)
    held = []

    def route(r):
        if not held and "before=" not in r.request.url:
            held.append(r)                                 # the refresh's Issues fetch
        else:
            r.continue_()
    page.route("**/api/sitetree/node?*", route)
    r0 = _count(page, "refreshes")
    with page.expect_request(lambda r: "/api/sitetree/node" in r.url
                             and "before=" not in r.url, timeout=15000):
        w = _Written(site, "/zz-b5b").__enter__()
    try:
        assert _until(page, lambda: held), "the refresh's Issues fetch was not held"
        page.click("#st-issues-more")                      # the user's page passes
        expect(rows).to_have_count(60)
        held[0].continue_()
        _reach(page, "refreshes", r0 + 1)
        expect(rows).to_have_count(60)
        hrefs = rows.locator("a").evaluate_all("els => els.map(e => e.getAttribute('href'))")
        assert len(hrefs) == len(set(hrefs)) == 60
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


def test_a_refresh_during_a_show_more_findings_load_still_delivers_that_page(tab, site):
    """E5, the click-first order (D6; B5b is the other): the user's "Show more findings"
    is in flight when a refresh starts and re-reads Issues. The refresh must deliver that
    page (60, never 50) exactly once, whichever answer lands last."""
    page = tab.page
    rows = _issues_60(tab)
    _baseline(page)
    held = []

    def route(r):
        if not held and "before=" in r.request.url:
            held.append(r)                                 # the user's page: held
        else:
            r.continue_()
    page.route("**/api/sitetree/node?*", route)
    with page.expect_request(lambda r: "/api/sitetree/node" in r.url and "before=" in r.url):
        page.click("#st-issues-more")
    assert _until(page, lambda: held), "the user's page was not held"
    r0 = _count(page, "refreshes")
    w = _Written(site, "/zz-b5c").__enter__()
    try:
        _reach(page, "refreshes", r0 + 1)                  # the refresh delivered the page
        expect(rows).to_have_count(60)
        loads = _count(page, "loads")
        held[0].continue_()                                # the user's answer lands last
        _reach(page, "loads", loads + 1)                   # ...and has been handled
        expect(rows).to_have_count(60)
        hrefs = rows.locator("a").evaluate_all("els => els.map(e => e.getAttribute('href'))")
        assert len(hrefs) == len(set(hrefs)) == 60
    finally:
        w.__exit__(None, None, None)
    assert tab.problems() == []


_FOCUSABLE = """(regions) => {
  const sel = 'a[href], button, input, select, textarea, [tabindex]';
  const out = [];
  for (const r of regions) {
    const root = document.querySelector(r);
    for (const e of root.querySelectorAll(sel)) {
      if (e.closest('[hidden]')) continue;
      out.push({region: r, tag: e.tagName, cls: String(e.getAttribute('class') || ''),
                key: e.getAttribute('data-focus-key')});
    }
  }
  return out;
}"""


def test_every_focusable_control_in_the_site_maps_live_regions_has_a_focus_key(tab):
    """FR-UI-514: each focusable control a refresh re-renders carries a focus key that
    names its identity (never its position), unique in its region (D5)."""
    page = tab.page
    _wide(tab)
    tab.open(ORIGIN, "shop")
    tab.item("item.php").first.locator(":scope > .st-row .st-label").click()   # select
    expect(page.locator("#st-issues-table tbody tr")).to_have_count(50)
    tab.open("item.php", "GET /shop/item.php", "id · query")                     # findings
    found = page.evaluate(_FOCUSABLE, ["#st-tree", "#st-issues"])
    kinds = {(f["tag"], f["cls"].split(" ")[0]) for f in found}
    assert {("LI", "st-item"), ("BUTTON", "st-count"), ("A", "st-open"),
            ("BUTTON", "st-more-btn"), ("A", "")} <= kinds        # every kind is present
    assert [f for f in found if not f["key"]] == []
    keys = [(f["region"], f["key"]) for f in found]
    assert len(keys) == len(set(keys))


def test_a_checkpoint_with_no_write_never_refreshes_the_page(tab, site):
    """E1 in the real app (p7): frames a writer (another process, D4) left in the WAL are
    folded by a reader's last close after the page's baseline; no commit happened, so
    nothing refreshes."""
    from fuzzlab.web.projects import open_reader
    page = tab.page
    roots = []
    page.on("request", lambda r: "/api/sitetree/children" in r.url and "node=" not in r.url
            and roots.append(r.url))
    reader = open_reader(str(site["path"]))
    try:
        reader.conn.execute("SELECT count(*) FROM endpoint").fetchall()
        with _Written(site, "/zz-l1b"):                    # two commits by another process
            pass                                           # content as before; frames stay
        page.reload()
        page.wait_for_selector('#sitetree-root[data-ready="1"] [role="treeitem"]')
        _baseline(page)
        polls, refreshes, base = _count(page, "polls"), _count(page, "refreshes"), len(roots)
    finally:
        reader.close()                                     # the last close folds the WAL
    _reach(page, "polls", polls + 3)                       # three complete polls after it
    assert _count(page, "refreshes") == refreshes
    assert len(roots) == base
    assert tab.problems() == []


# --- B9 (D7): focus counts only where it lands, ends at the pane, never scrolls ----------

_B9_HELPER = """async () => {
  const lf = await import("/static/js/livefocus.js");
  const mk = (tag, text) => { const e = document.createElement(tag); e.textContent = text; return e; };
  const out = {};
  const pane = mk("div", "");
  pane.tabIndex = -1;
  document.querySelector("#sitetree-root").append(pane);
  // 1. the keyed control comes back disabled; then a hidden, a detached and a visible but
  //    unfocusable candidate, and a function finding nothing: each refuses focus
  let first = mk("button", "first");
  first.dataset.focusKey = "k";
  pane.append(first);
  first.focus();
  const key = lf.focusKeyIn(pane);
  pane.replaceChildren();
  const disabled = mk("button", "disabled");
  disabled.dataset.focusKey = "k";
  disabled.disabled = true;
  const box = mk("div", "");
  box.hidden = true;
  const hidden = mk("button", "hidden");
  box.append(hidden);
  const detached = mk("button", "detached");
  const inert = mk("div", "visible but unfocusable");
  const spacer = mk("div", "");
  spacer.style.height = "4000px";                  // CSSOM, allowed by the page's CSP
  const visible = mk("button", "visible");
  pane.append(disabled, box, inert, spacer, visible);
  window.scrollTo(0, 0);
  out.key = key;
  out.lostToBody = document.activeElement === document.body;
  let got = lf.restoreFocus(pane, key, hidden, detached, inert, () => null, visible);
  out.landed = got === visible && document.activeElement === visible;
  out.scrollY = window.scrollY;                     // preventScroll: 4000 px down, unscrolled
  // 2. nothing usable is left: the pane itself, never the body
  pane.replaceChildren(mk("button", "second"));
  pane.firstChild.dataset.focusKey = "k2";
  pane.firstChild.focus();
  const key2 = lf.focusKeyIn(pane);
  pane.replaceChildren(box);
  got = lf.restoreFocus(pane, key2, hidden, detached, () => null);
  out.pane = got === pane && document.activeElement === pane;
  // 3. focus outside the region is never taken; focus still inside it is never moved
  const outside = document.querySelector("#st-q");
  outside.focus();
  out.notStolen = lf.restoreFocus(pane, lf.focusKeyIn(pane), visible) === null
    && document.activeElement === outside;
  pane.replaceChildren(visible);
  visible.focus();
  const other = mk("button", "other");
  pane.append(other);
  out.kept = lf.restoreFocus(pane, "k", other) === visible && document.activeElement === visible;
  pane.remove();
  return out;
}"""


def test_restore_focus_skips_every_candidate_that_refuses_focus_and_ends_at_the_pane(tab):
    """B9, the helper (D7): a candidate counts only where focus actually landed. A
    disabled keyed control, a hidden, a detached and a visible-but-unfocusable fallback
    and a function finding nothing are each skipped, and a visible fallback takes focus
    without scrolling (preventScroll: 4000 px below the viewport). With nothing usable
    left, the region's pane takes it -- never the page body. Focus outside the region is
    never taken, and focus still inside it is never moved."""
    out = tab.page.evaluate(_B9_HELPER)
    assert out == {"key": "k", "lostToBody": True, "landed": True, "scrollY": 0,
                   "pane": True, "notStolen": True, "kept": True}, out
    assert tab.problems() == []


def test_a_refresh_that_removes_the_focused_item_never_scrolls_nor_drops_to_the_body(tab,
                                                                                    site):
    """B9, in a real refresh (D7): the focused item is deleted (another process); focus
    goes to its parent item, which is scrolled out of the tree pane's view, and the pane
    does not scroll (preventScroll). Then, with a run lens showing one host, that host's
    rows are deleted: the tree is empty and focus ends at the tree's pane, never <body>."""
    page = tab.page
    group = _wide(tab)
    _baseline(page)
    pane = page.locator(".st-tree-pane")
    pane.evaluate("e => { e.style.overflowAnchor = 'none'; }")  # no scroll anchoring
    w150 = tab.item("w150").first
    w150.scroll_into_view_if_needed()
    w150.focus()                                            # focus only: no select, no expand
    expect(w150).to_be_focused()
    top = pane.evaluate("e => e.scrollTop")
    wide_row = tab.item("wide").first.locator(":scope > .st-row")
    assert top > 0 and wide_row.evaluate(
        "(row, pane) => row.getBoundingClientRect().bottom < pane.getBoundingClientRect().top",
        pane.element_handle()), "the parent item is in view: the case proves nothing"
    r0 = _count(page, "refreshes")
    _xsql(site, "DELETE FROM endpoint WHERE url='/wide/w150'")
    try:
        _reach(page, "refreshes", r0 + 1)
        expect(group.locator(":scope > li[role=treeitem]")).to_have_count(200)
        assert _focused_item(page)[1] == "wide"
        assert pane.evaluate("e => e.scrollTop") == top
    finally:
        _xsql(site, "INSERT INTO endpoint (run_id, url, method) VALUES (?, '/wide/w150', "
              "'GET')", site["a"])
    page.select_option("#st-run", str(site["b"]))           # one host: run b's
    hosts = page.locator('#st-tree > li[role="treeitem"]')
    expect(hosts).to_have_count(1)
    hosts.first.focus()
    r0 = _count(page, "refreshes")
    _xsql(site, "DELETE FROM endpoint WHERE run_id=?", site["b"])
    try:
        _reach(page, "refreshes", r0 + 1)
        expect(hosts).to_have_count(0)
        assert page.evaluate("() => document.activeElement.id") == "st-tree"
    finally:
        _xsql(site, "INSERT INTO endpoint (run_id, url, method) VALUES (?, '/crawl/only', "
              "'GET')", site["b"])
    assert tab.problems() == []


def test_a_refresh_whose_group_fetch_fails_is_retried_at_the_next_poll(tab, site):
    """FR-UI-505 (blocker 6): a version is marked seen only once its refresh succeeded.
    The refresh's fetch of an expanded group fails once (an injected 500): the page keeps
    the old version, and a later poll's refresh shows the write. Before, the poll
    recorded the version first and the failed group was never re-read."""
    page = tab.page
    _wide(tab)
    _baseline(page)
    failed = []

    def route(r):
        if not failed and "wide" in r.request.url and "after=" not in r.request.url:
            failed.append(r.request.url)
            r.fulfill(status=500, content_type="application/json",
                      body='{"error": "injected"}')
        else:
            r.continue_()
    page.route("**/api/sitetree/children?*", route)
    r0 = _count(page, "refreshes")
    w = _Written(site, "/wide/w0005").__enter__()
    try:
        _reach(page, "refreshes", r0 + 1)
        assert failed, "the group's fetch never failed: the case proves nothing"
        expect(tab.item("w0005").first).to_be_attached()
        assert _count(page, "refreshes") == r0 + 1
    finally:
        w.__exit__(None, None, None)
    assert [p for p in tab.problems() if "status of 500" not in p] == []
