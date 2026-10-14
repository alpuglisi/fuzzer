"""Forms phase 1: navigate an app as shipped, and fuzz its forms with their siblings.

Found against the operator's loopback bWAPP: its pages are reachable only through a
POST "pick a bug" form, and most sinks run only when the whole form is sent
(``form=submit``, both ``firstname`` and ``lastname``). The rules here are generic;
reviewers A/B fixed the safety envelope (FR-CRAWL-8/9, FR-FUZZ-42, FR-CORE-29).
"""

import ast
import json
import sqlite3
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core.forms import form_record, is_selector_form
from fuzzlab.core.store import Store
from fuzzlab.core.urls import destructive_reason
from fuzzlab.harness.auto import injection_points_from_store, run_auto
from fuzzlab.oracle.oracle import Oracle, _FormBoundSender
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.tools import formnav
from fuzzlab.tools.store_adapter import form_skip_reason, import_spider

ROOT = Path(__file__).resolve().parents[1]


def _rec(html, page="http://h/app/portal.php"):
    return form_record(BeautifulSoup(html, "html.parser").find("form"), page)


PICKER = """<form action="/app/portal.php" method="POST">
  <select name="bug" size="9">
    <option value="0">----- app v1 -----</option>
    <option value="2">HTML Injection - Reflected (GET)</option>
    <option value="3">/ A5 - Security Misconfiguration /</option>
    <option value="4">Unprotected Admin Portal</option>
    <option value="5">Broken Auth - Logout</option>
    <option value="6">SQL Injection (GET/Search)</option>
  </select><button type="submit" name="form" value="submit">Go</button></form>"""
LEVEL = """<form action="/app/portal.php" method="POST">
  <select name="security_level"><option value="0">low</option><option value="1">medium</option>
  </select><button type="submit" name="form_security_level" value="submit">Set</button></form>"""


# --- selector navigation: the gate before any submission ---------------------------
def test_selector_forms_are_recognised():
    assert is_selector_form(BeautifulSoup(PICKER, "html.parser").find("form"))
    assert not is_selector_form(BeautifulSoup(
        "<form><select name=a></select><input name=q></form>", "html.parser").find("form"))


def test_a_post_picker_is_submitted_only_when_its_select_is_named():
    rec, ok = _rec(PICKER), (lambda u: True)
    assert "not named" in formnav.refusal(rec, frozenset(), True, ok)
    assert formnav.refusal(rec, frozenset({"bug"}), True, ok) is None


def test_a_settings_picker_is_never_submitted_even_when_named():
    assert "settings" in formnav.refusal(_rec(LEVEL), frozenset({"security_level"}), True,
                                         lambda u: True)


def test_a_destructive_or_out_of_scope_action_is_never_submitted():
    rec = _rec(PICKER.replace("/app/portal.php", "/app/reset.php"))
    assert "destructive" in formnav.refusal(rec, frozenset({"bug"}), True, lambda u: True)
    assert "scope" in formnav.refusal(_rec(PICKER), frozenset({"bug"}), True,
                                      lambda u: False)


def test_a_get_picker_is_allowed_whenever_the_feature_is_on():
    rec = _rec(PICKER.replace('method="POST"', 'method="GET"'))
    assert formnav.refusal(rec, frozenset(), True, lambda u: True) is None
    assert formnav.refusal(rec, frozenset(), False, lambda u: True) is not None


class _App:
    """An app's picker endpoint: each option redirects to its page."""

    def __init__(self, pages=None, cookie_on=None, status_on=None):
        self.sent = []
        self.pages = pages or {"0": "portal.php", "2": "htmli_get.php",
                               "3": "x.php", "4": "y.php", "5": "z.php",
                               "6": "sqli_1.php"}
        self.cookie_on, self.status_on = cookie_on, status_on or {}

    def submit(self, method, url, entries):
        value = dict(entries)["bug"]
        self.sent.append(value)
        headers = {"Location": self.pages.get(value, "portal.php")}
        if value == self.cookie_on:
            headers["Set-Cookie"] = "security_level=1"
        return self.status_on.get(value, 302), headers


def test_enumeration_skips_settings_and_destructive_options_and_self_redirects():
    app = _App()
    found = formnav.enumerate_form(_rec(PICKER), app.submit, lambda u: True)
    assert found == ["http://h/app/htmli_get.php", "http://h/app/sqli_1.php"]
    assert app.sent == ["0", "2", "6"]          # 3 security, 4 admin, 5 logout: never sent


def test_a_cookie_or_a_non_redirect_stops_enumeration():
    assert formnav.enumerate_form(_rec(PICKER), _App(cookie_on="2").submit,
                                  lambda u: True) == []
    assert formnav.enumerate_form(_rec(PICKER), _App(status_on={"2": 200}).submit,
                                  lambda u: True) == []


def test_a_destructive_or_out_of_scope_location_stops_and_is_not_queued():
    app = _App(pages={"0": "portal.php", "2": "update.php", "6": "sqli_1.php"})
    assert formnav.enumerate_form(_rec(PICKER), app.submit, lambda u: True) == []
    app = _App(pages={"0": "portal.php", "2": "http://evil.example/", "6": "s.php"})
    assert formnav.enumerate_form(_rec(PICKER), app.submit,
                                  lambda u: "evil" not in u) == []


def test_five_self_redirects_mark_a_settings_form():
    many = "".join(f"<option value='{i}'>opt {i}</option>" for i in range(8))
    rec = _rec(f"<form action='/app/s.php' method='POST'><select name='bug'>{many}"
               f"</select><button name='go' value='1'>Go</button></form>",
               page="http://h/app/s.php")
    app = _App(pages={str(i): "s.php" for i in range(8)})
    assert formnav.enumerate_form(rec, app.submit, lambda u: True) == []
    assert len(app.sent) == 5


# --- the crawler: off by default, isolated cookies, records forms and landings -------
class _Resp:
    def __init__(self, status, text="", headers=None, url=None):
        self.status_code, self.text, self.url = status, text, url
        self.headers = {"Content-Type": "text/html", **(headers or {})}


class _Site:
    def __init__(self):
        self.gets, self.posts = [], []
        self.cookies = __import__("requests").cookies.RequestsCookieJar()
        self.headers = {}

    def get(self, url, timeout=None, allow_redirects=True, params=None):
        self.gets.append(url)
        if params:
            self.posts.append(dict(params))
            return _Resp(302, headers={"Location": "a_page.php"})
        if url.endswith("portal.php"):
            return _Resp(200, "<html>" + PICKER + LEVEL +
                         "<form method=get action='/app/menu.php'><select name=page>"
                         "<option value=a>A</option></select></form>" +
                         "<form method=post action='/app/c.php'>"
                         "<input type=hidden name=csrf_token value=SECRET123>"
                         "<input name=title></form></html>", url=url)
        if url.endswith("go.php"):
            return _Resp(302, headers={"Location": "land.php?session=TOPSECRET&x=1"},
                         url=url)
        return _Resp(200, "<html>page</html>", url=url)

    def post(self, url, data=None, allow_redirects=True, timeout=None):
        self.posts.append(dict(data))
        value = dict(data).get("bug")
        self.cookies.set("last_post", "1")          # a response cookie lands in THIS jar
        if "security_level" in dict(data):
            return _Resp(302, headers={"Location": "portal.php",
                                       "Set-Cookie": "security_level=1"})
        return _Resp(302, headers={"Location": {"2": "htmli_get.php",
                                                "6": "sqli_1.php"}.get(value, "portal.php")})


def _spider(tmp_path, monkeypatch, selector_forms):
    from fuzzlab.tools import spider as spider_mod
    sp = spider_mod.LocalSpider("http://h/app/portal.php", max_depth=1,
                                db_name=str(tmp_path / "s.db"), engine="requests",
                                selector_forms=selector_forms)
    site = _Site()
    sp.session = site
    monkeypatch.setattr(spider_mod.requests, "Session", lambda: site)
    return sp, site


def test_selector_navigation_is_off_by_default(tmp_path, monkeypatch):
    sp, site = _spider(tmp_path, monkeypatch, None)
    sp.crawl()
    assert site.posts == []                     # neither the POST nor the GET picker


def test_a_named_picker_is_navigated_and_the_settings_one_never_touched(tmp_path,
                                                                        monkeypatch):
    sp, site = _spider(tmp_path, monkeypatch, ["bug"])
    sp.crawl()
    assert all("security_level" not in p for p in site.posts)
    assert "http://h/app/htmli_get.php" in site.gets and "http://h/app/sqli_1.php" in site.gets
    rows = {r[0]: r[1] for r in sqlite3.connect(tmp_path / "s.db").execute(
        "SELECT url, source FROM discovered_pages")}
    assert rows["http://h/app/sqli_1.php"] == "form"


def test_selector_submissions_never_change_the_crawlers_cookies(tmp_path, monkeypatch):
    """Even a response that sets a cookie (a settings form) must not reach the jar."""
    from fuzzlab.tools import spider as spider_mod
    sp, site = _spider(tmp_path, monkeypatch, ["bug"])

    class Iso(_Site):
        def post(self, url, data=None, allow_redirects=True, timeout=None):
            self.cookies.set("security_level", "1")      # a response cookie
            return _Resp(302, headers={"Location": "x.php", "Set-Cookie": "security_level=1"})
    iso = Iso()
    monkeypatch.setattr(spider_mod.requests, "Session", lambda: iso)
    sp._isolated_submit("POST", "http://h/app/portal.php", [("bug", "2")])
    assert "security_level" not in site.cookies and "last_post" not in site.cookies
    assert iso.cookies.get("security_level") == "1"       # it landed in the throwaway jar


def test_forms_are_recorded_with_secrets_blanked(tmp_path, monkeypatch):
    sp, _site = _spider(tmp_path, monkeypatch, None)
    sp.crawl()
    db = sqlite3.connect(tmp_path / "s.db")
    entries = [json.loads(r[0]) for r in db.execute("SELECT entries FROM discovered_forms")]
    assert any(["csrf_token", ""] in e for e in entries)
    assert "SECRET123" not in json.dumps(entries)


def test_a_redirect_landing_is_recorded_with_its_query_redacted(tmp_path, monkeypatch):
    from fuzzlab.tools import spider as spider_mod
    sp = spider_mod.LocalSpider("http://h/app/go.php", max_depth=0,
                                db_name=str(tmp_path / "s.db"), engine="requests")

    class Hop(_Site):
        def get(self, url, timeout=None, allow_redirects=True, params=None):
            self.gets.append(url)
            if url.endswith("go.php"):
                return _Resp(302, headers={"Location": "land.php?session=TOPSECRET&x=1"},
                             url=url)
            return _Resp(200, "<html>landed</html>", url=url)
    sp.session = Hop()
    sp.crawl()
    urls = [r[0] for r in sqlite3.connect(tmp_path / "s.db").execute(
        "SELECT url FROM discovered_pages")]
    landed = [u for u in urls if "land.php" in u]
    assert landed and "x=1" in landed[0] and "TOPSECRET" not in landed[0]


def test_the_form_producer_goes_through_redaction():
    """PA-0100: the function that INSERTs discovered forms calls redact_url, and its
    entries come from form_record (which blanks sensitive values)."""
    tree = ast.parse((ROOT / "fuzzlab/tools/spider.py").read_text())
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        consts = [n.value for n in ast.walk(fn) if isinstance(n, ast.Constant)
                  and isinstance(n.value, str)]
        if any("INSERT INTO discovered_forms" in c for c in consts):
            called = {getattr(c.func, "id", getattr(c.func, "attr", None))
                      for c in ast.walk(fn) if isinstance(c, ast.Call)}
            assert "redact_url" in called
            return
    pytest.fail("no discovered_forms producer found")


# --- import: forms become points, with the agreed exclusions -------------------------
def _spider_db(path, forms, pages=()):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT, "
               "depth INT)")
    db.executemany("INSERT INTO discovered_pages VALUES (?,?,?,0)",
                   [(u, 200, "link") for u in pages])
    db.execute("CREATE TABLE discovered_forms (page_url TEXT, action_url TEXT, method TEXT, "
               "enctype TEXT, entries TEXT, controls TEXT, selector INT, options TEXT)")
    for f in forms:
        db.execute("INSERT INTO discovered_forms VALUES (?,?,?,?,?,?,?,?)",
                   (f["page_url"], f["action_url"], f["method"], f["enctype"],
                    json.dumps(f["entries"]), json.dumps(f["controls"]),
                    int(f["selector"]), json.dumps(f["options"])))
    db.commit()
    db.close()


def _points(tmp_path, html_forms, pages=(), base="http://h/app/"):
    recs = [_rec(h, page="http://h/app/p.php") for h in html_forms]
    _spider_db(tmp_path / "s.db", recs, pages)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        counts = import_spider(tmp_path / "s.db", store, run)
        skipped = []
        return injection_points_from_store(store, run, base, skipped=skipped), skipped, counts


def test_post_and_get_forms_become_points_with_their_siblings(tmp_path):
    pts, _s, _c = _points(tmp_path, [
        "<form method=post action='/app/xss_post.php?lang=en'><input name=firstname>"
        "<input name=lastname><button name=form value=submit>Go</button></form>",
        "<form method=get action='/app/sqli_1.php?page=2'><input name=title>"
        "<button name=action value=search>Search</button></form>"])
    by = {(p.url, p.param): p for p in pts}
    post = by[("http://h/app/xss_post.php?lang=en", "firstname")]
    assert post.method == "POST" and post.location == "body"
    assert post.base_entries == (("firstname", "fuzzlab"), ("lastname", "fuzzlab"),
                                 ("form", "submit"))
    assert ("http://h/app/xss_post.php?lang=en", "form") not in by      # submitter
    get = by[("http://h/app/sqli_1.php", "title")]                      # query dropped
    assert get.location == "query" and ("action", "search") in get.base_entries


@pytest.mark.parametrize("html,why", [
    # forms phase 2 (FR-FUZZ-44) lifted the blanket password exclusion: a plain login
    # form is now imported (probed on an isolated session); a credential changer is not
    ("<form method=post><input name=login><input type=password name=password_new>"
     "<input type=password name=password_conf></form>", "credential-change"),
    ("<form method=post enctype='multipart/form-data'><input type=file name=f>"
     "<input name=t></form>", "multipart"),
    # FR-FUZZ-42's "never a POST selector" is superseded by FR-FUZZ-43 (forms phase 2):
    # a POST picker is skipped only when a control name is a settings word -- the
    # select's, or only the submitter's
    (LEVEL, "settings"),
    ("<form method=post action='/app/p.php'><select name=movie><option value=1>A"
     "</option></select><button name=set_default value=go>Go</button></form>",
     "settings"),
    ("<form method=post action='/app/blog.php'><textarea name=entry></textarea>"
     "<button name=entry_delete value=del>Delete</button>"
     "<button name=entry_add value=add>Add</button></form>", "destructive"),
    ("<form method=post><input name=q><input type=checkbox name=delete_all checked></form>",
     "destructive"),
])
def test_unsafe_forms_are_never_imported(html, why):
    reason = form_skip_reason({**_rec(html), "enctype": _rec(html)["enctype"]})
    assert reason and why.split()[0] in reason


def test_object_selecting_hidden_fields_and_csrf_are_pinned_not_fuzzed(tmp_path):
    pts, _s, _c = _points(tmp_path, [
        "<form method=post action='/app/s.php'><input type=hidden name=login value=bee>"
        "<input type=hidden name=user_id value=7><input type=hidden name=csrf_token value=T>"
        "<input name=secret_note><input name=comment></form>"])
    names = {p.param for p in pts}
    assert names == {"comment"}                      # secret_* is a credential name too
    entries = dict(pts[0].base_entries)
    assert entries["login"] == "bee" and entries["csrf_token"] == ""


def test_credential_parameters_from_links_are_never_fuzzed(tmp_path):
    pts, skipped, _c = _points(tmp_path, [], pages=[
        "http://h/app/csrf_1.php?password_new=a&password_conf=a&action=change"])
    assert {p.param for p in pts} == {"action"}
    assert {s[2] for s in skipped} >= {"password_new", "password_conf"}


def test_blank_query_values_are_parameters(tmp_path):
    pts, _s, _c = _points(tmp_path, [], pages=["http://h/app/xss_ajax_1-2.php?title="])
    assert [p.param for p in pts] == ["title"]


def test_ground_truth_password_points_are_unaffected():
    from fuzzlab.harness.auto import points_from_ground_truth
    from fuzzlab.labels import contract
    pts, _ = points_from_ground_truth(contract.load("lab/ground-truth"), "http://h")
    assert any(p.param == "password" for p in pts)


# --- sending: one binding point, every sender honours entries -----------------------
class _Rec:
    def __init__(self):
        self.calls = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        self.calls.append((url, param, value, method, location, entries))
        return Probe(200, "ok")


def _cand(**kw):
    base = dict(url="http://h/app/x.php", param="firstname", method="POST",
                location="body",
                base_entries=(("firstname", ""), ("lastname", ""), ("csrf", ""),
                              ("form", "submit")))
    base.update(kw)
    return Candidate(**base)


def test_the_form_binding_sends_the_full_entry_list_with_the_target_replaced():
    inner = _Rec()
    _FormBoundSender(inner, _cand()).send("http://h/app/x.php", "firstname", "<b>",
                                          method="POST", location="body")
    entries = list(inner.calls[0][5])
    assert entries == [("firstname", "<b>"), ("lastname", ""), ("csrf", ""),
                       ("form", "submit")]             # a redacted sibling is sent empty


def test_the_binding_leaves_other_urls_and_methods_alone():
    inner = _Rec()
    b = _FormBoundSender(inner, _cand())
    b.send("http://h/app/view.php", "firstname", "x", method="POST", location="body")
    b.send("http://h/app/x.php", "firstname", "x", method="GET", location="query")
    assert [c[5] for c in inner.calls] == [None, None]


def _sender_chain(sender):
    """The class names of a sender and every sender it wraps (outermost first)."""
    chain = []
    while sender is not None:
        chain.append(type(sender).__name__)
        sender = vars(sender).get("_inner")
    return chain


class _ChainSeen:
    """A strategy that records the sender chain it was handed."""
    arm = "s"

    def __init__(self):
        self.seen = []

    def applies(self, c):
        return True

    def confirm(self, c, sender):
        self.seen.append(_sender_chain(sender))


def test_the_oracle_binds_a_form_candidate_and_only_then():
    """A form candidate's strategy sends through `_FormBoundSender` (somewhere in its
    sender chain); a non-form candidate's never does. The chain is walked through the
    wrappers' ``_inner``, so the other wrappers (FR-SESS-20's `_SessionNotes`, the
    scheduler's `_CostCounter`) do not hide the binding."""
    s = _ChainSeen()
    Oracle(strategies=[s]).confirm(_cand(), _Rec())
    Oracle(strategies=[s]).confirm(_cand(base_entries=None), _Rec())
    form, plain = s.seen
    assert "_FormBoundSender" in form and form[-1] == "_Rec"
    assert "_FormBoundSender" not in plain and plain[-1] == "_Rec"


class _OneArm:
    """A minimal scheduler: keeps the order, records nothing."""

    def order(self, ctx, arms):
        return list(arms)

    def update(self, ctx, arm, reward, cost=1):
        pass


@pytest.mark.parametrize("scheduler,chain", [
    (None, ["_SessionNotes", "_FormBoundSender", "_Rec"]),
    (_OneArm(), ["_CostCounter", "_SessionNotes", "_FormBoundSender", "_Rec"]),
])
def test_the_oracle_wraps_the_sender_in_a_fixed_order(scheduler, chain):
    """The intended order (CC-FUZZ-0080): `_SessionNotes` outermost without a
    scheduler, `_CostCounter(_SessionNotes(...))` with one; the form binding is inside
    both, so every send the run makes is bound, noted and counted."""
    s = _ChainSeen()
    Oracle(strategies=[s], scheduler=scheduler).confirm(_cand(), _Rec())
    assert s.seen == [chain]


def test_requests_sender_sends_entries_as_body_or_query():
    from fuzzlab.tools.probesender import RequestsProbeSender
    calls = []

    class S:
        cookies = {}

        def request(self, method, url, **kw):
            calls.append((method, url, kw.get("data"), kw.get("params")))

            class R:
                status_code, text, headers = 200, "ok", {}
            return R()
    s = RequestsProbeSender(session=S())
    s.send("http://h/a.php", "q", "x", method="POST", location="body",
           entries=[("q", "x"), ("form", "submit")])
    s.send("http://h/a.php?old=1", "q", "x", method="GET", location="query",
           entries=[("q", "x"), ("action", "search")])
    assert calls[0][2] == [("q", "x"), ("form", "submit")]
    assert calls[1][1] == "http://h/a.php?q=x&action=search"


def test_every_probe_sender_accepts_entries():
    from tests.test_destructive_urls import SENDER_METHODS
    missing = []
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        for cls in [n for n in ast.walk(ast.parse(path.read_text()))
                    if isinstance(n, ast.ClassDef)]:
            for fn in cls.body:
                if isinstance(fn, ast.FunctionDef) and fn.name in SENDER_METHODS:
                    args = [a.arg for a in fn.args.args] + \
                           [a.arg for a in fn.args.kwonlyargs]
                    if args[:4] == ["self", "url", "param", "value"] and \
                            "entries" not in args and fn.name != "get":
                        missing.append(f"{path.name}:{cls.name}.{fn.name}")
    assert missing == []


# --- end to end: a page that only runs when the whole form is sent --------------------
class _TwoFieldApp:
    """A POST page that runs its (vulnerable) query only when both fields and the
    submit button are present."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None):
        data = dict(entries or [(param, value)])
        if method == "POST" and {"firstname", "lastname", "form"} <= set(data):
            if "'" in data["firstname"] or "'" in data["lastname"]:
                return Probe(200, "You have an error in your SQL syntax")
            return Probe(200, "<html>Welcome</html>")
        return Probe(200, "<html>form</html>")


def test_a_two_field_form_is_confirmed_only_with_its_siblings(tmp_path):
    _spider_db(tmp_path / "s.db", [_rec(
        "<form method=post action='/app/sqli_6.php'><input name=firstname>"
        "<input name=lastname><button name=form value=submit>Go</button></form>",
        page="http://h/app/sqli_6.php")])
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        import_spider(tmp_path / "s.db", store, run)
        result = run_auto(base_url="http://h/app/", store=store, run_id=run,
                          sender=_TwoFieldApp(), mode="manual",
                          selected_categories=["sql-injection"], points_source="crawl")
        assert result.findings >= 1


# --- PA-0114: the adopted lab's destructive endpoints, from its source ----------------
#: bWAPP v2.2 GET endpoints that destroy or rewrite lab state on a visit (from its
#: source, scratchpad gap map section (b)); each must be refused by the deny rule.
BWAPP_DESTRUCTIVE_GETS = [
    "/bWAPP/reset.php", "/bWAPP/update.php", "/bWAPP/install.php?install=yes",
    "/bWAPP/logout.php", "/bWAPP/ba_logout.php",
    "/bWAPP/insecure_crypt_storage_2.php?delete=", "/bWAPP/insecure_crypt_storage_2.php?insert=",
]
#: Known not caught by the URL rule, with what covers them instead.
BWAPP_NOT_URL_CAUGHT = {
    "/bWAPP/restrict_folder_access.php": "residual: a visit deletes documents/.htaccess "
                                         "(the page's own demo); stated in FR-CRAWL-8",
    "/bWAPP/csrf_1.php?password_new=x&password_conf=x&action=change":
        "credential parameters are never fuzzed (injection_points_from_store)",
}


@pytest.mark.parametrize("path", BWAPP_DESTRUCTIVE_GETS)
def test_bwapps_destructive_gets_are_refused(path):
    assert destructive_reason("http://127.0.0.1:8090" + path) is not None


def test_bwapps_uncaught_endpoints_are_known_and_covered_elsewhere():
    from fuzzlab.harness.auto import _credential_name
    assert _credential_name("password_new")
    assert all(destructive_reason("http://h" + p) is None for p in BWAPP_NOT_URL_CAUGHT)


def test_empty_text_siblings_are_filled_as_a_user_would(tmp_path):
    """Live (bWAPP xss_get): the page ignores a request whose other name is empty."""
    pts, _s, _c = _points(tmp_path, [
        "<form method=get action='/app/xss_get.php'><input name=firstname>"
        "<input name=lastname><input type=email name=mail><input type=url name=site>"
        "<input type=hidden name=h>"
        "<input type=hidden name=csrf value=T><select name=s><option value=a>a</option>"
        "</select><button name=form value=submit>Go</button></form>"])
    entries = dict(pts[0].base_entries)
    assert entries["lastname"] == "fuzzlab" and entries["mail"] == "fuzzlab@example.invalid"
    assert entries["h"] == "" and entries["csrf"] == "" and entries["s"] == "a"
    assert entries["site"].endswith(".invalid/")          # never resolves: no fetch
