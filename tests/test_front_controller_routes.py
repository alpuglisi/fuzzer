"""A front controller's pages (``index.php?page=...``) as distinct findings, scored cases,
logins and auth endpoints (FR-FUZZ-622, CC-SESS-0610, CC-SESS-0611; CC-FUZZ-0622,
CC-SESS-0610, CC-SESS-0611; SP-90). Measured on Mutillidae II 2.12.8 (CC-LAB-0343):
every page is ``/index.php``, its login is ``index.php?page=login.php`` and is linked
only from the home page."""

from __future__ import annotations

import glob
from pathlib import Path

import pytest

from fuzzlab.oracle.oracle import finding_url
from fuzzlab.oracle.probe import Candidate

REPO = Path(__file__).resolve().parent.parent


# --- the finding URL (SP-90) ----------------------------------------------------------

@pytest.mark.parametrize("url,param,entries,want", [
    ("http://h/index.php?page=user-info.php&username=x", "username", None,
     "/index.php?page=user-info.php"),
    # a crawled point carries its query as siblings (forms phase 2)
    ("http://h/index.php", "uid", (("page", "view-account-profile.php"), ("uid", "41")),
     "/index.php?page=view-account-profile.php"),
    # the probed parameter is the route: its value is the payload, never kept
    ("http://h/index.php?page=user-info.php", "page", None, "/index.php"),
    ("http://h/index.php", "page", (("page", "home.php"),), "/index.php"),
    # not a plain page name: nothing of the query is kept
    ("http://h/index.php?page=%3Cscript%3E", "q", None, "/index.php"),
    ("http://h/index.php?page=a%20b", "q", None, "/index.php"),
    # not a router, or no route parameter: the path, as before
    ("http://h/app/search.php?page=2&q=x", "q", None, "/app/search.php"),
    ("http://h/index.php?id=4", "id", None, "/index.php"),
    ("http://h/bWAPP/sqli_1.php?title=x", "title", None, "/bWAPP/sqli_1.php"),
])
def test_a_front_controllers_route_is_part_of_the_finding_url(url, param, entries, want):
    assert finding_url(Candidate(url=url, param=param, base_entries=entries)) == want


def test_a_fragment_point_keeps_its_hash_route_unchanged():
    assert finding_url(Candidate(url="http://h/#/search?q=x", param="q",
                                 location="fragment")) == "/#/search"


def test_the_route_names_are_the_login_detectors():
    """SP-90: one decision of what a front controller is -- `session.detect`'s router
    and route names, read, never restated."""
    import inspect

    from fuzzlab.oracle import oracle
    src = inspect.getsource(oracle._front_controller_route)
    assert "_ROUTER_SEGMENTS" in src and "_ROUTE_PARAMS" in src
    assert "frozenset(" not in src and "{\"page\"" not in src


# --- scoring --------------------------------------------------------------------------

def test_the_scoring_key_of_every_plain_path_case_is_unchanged():
    """Guard (FR-FUZZ-622): `case_key` changes no case of any answer key whose URL is a
    plain path -- every key before Mutillidae's."""
    from fuzzlab.harness.scoring import case_key
    from fuzzlab.labels import contract
    seen = 0
    for d in sorted(glob.glob(str(REPO / "lab" / "ground-truth*"))):
        for case in contract.load(d).cases:
            if "?" not in case.url:
                assert case_key(case) == case.key, (d, case.case_id)
                seen += 1
    assert seen > 100


def test_a_routed_case_matches_the_finding_its_point_produces():
    from fuzzlab.harness.scoring import Detection, case_key, score
    from fuzzlab.labels import contract
    gt = contract.load(REPO / "lab" / "ground-truth-mutillidae")
    routed = [c for c in gt.positives() if "&" in c.url]
    assert routed
    c = routed[0]
    det = Detection(finding_url(Candidate(url="http://127.0.0.1:1" + c.url, param=c.param,
                                          method=c.method, location=c.location)),
                    c.method, c.param, c.vuln_class)
    assert det.key == case_key(c)
    report = score([det], gt)
    assert report.tp == 1 and report.fp == 0 and c.case_id in report.matched


def test_two_pages_of_one_front_controller_are_two_cases():
    """user-info.php's username is SQL injection; user-info-xpath.php's is not."""
    from fuzzlab.harness.scoring import case_key
    from fuzzlab.labels import contract
    gt = contract.load(REPO / "lab" / "ground-truth-mutillidae")
    keys = {}
    for c in gt.cases:
        if c.param == "username" and c.vuln_class == "sqli":
            keys[case_key(c)] = c.expected_vulnerable
    assert sorted(keys.values()) == [False, True]


# --- login discovery (CC-SESS-0610) ----------------------------------------------------

_HOME = """<html><body>
<a href="index.php?page=login.php">Login/Register</a>
<a href="index.php?page=home.php">Home</a>
<a href="http://127.0.0.1:9/elsewhere/login.php">another port's login</a>
<a href="https://evil.example/login">off-site</a>
<a href="index.php?do=logout">Logout</a>
<a href="index.php?page=login.php#top">again</a>
<a href="/signin">a</a><a href="/accounts/login">b</a><a href="/sessions/new">c</a>
</body></html>"""


def test_the_base_pages_own_login_links_are_candidates():
    from fuzzlab.session.manager import SessionManager
    got = SessionManager._linked_login_urls(_HOME, "http://127.0.0.1:3093/",
                                            ["http://127.0.0.1:3093/",
                                             "http://127.0.0.1:3093/signin"])
    # same origin only, login-shaped only (never logout), deduplicated (a fragment
    # removed), not a known candidate, page order, at most MAX_LINKED_LOGIN_PAGES
    assert got == ["http://127.0.0.1:3093/index.php?page=login.php",
                   "http://127.0.0.1:3093/accounts/login",
                   "http://127.0.0.1:3093/sessions/new"]
    assert len(got) <= SessionManager.MAX_LINKED_LOGIN_PAGES


def test_login_discovery_reaches_a_query_routed_login_from_the_base_page():
    from fuzzlab.session.manager import SessionManager

    login = ('<form method="post" action="index.php?page=login.php">'
             '<input name="username"><input type="password" name="password">'
             '<input type="submit" name="login-php-submit-button" value="Login"></form>')
    pages = {"http://127.0.0.1:3093/": _HOME,
             "http://127.0.0.1:3093/index.php?page=login.php": login}
    fetched = []

    class _Resp:
        def __init__(self, url):
            self.status = 200 if url in pages else 404
            self.text = pages.get(url, "not found")
            self.headers = {}

    mgr = SessionManager.__new__(SessionManager)

    def navigate(fetcher, url, base_url, floor, seen=None):
        fetched.append(url)
        return _Resp(url), url, False
    mgr._navigate = navigate
    form, page, challenge, _floor = mgr._discover_login_form(None, "http://127.0.0.1:3093/",
                                                              unread=[])
    assert form is not None and page == "http://127.0.0.1:3093/index.php?page=login.php"
    assert form.password_field == "password"
    # the fixed candidates first, then the linked login page; nothing else fetched
    assert fetched[-1] == page and fetched[0] == "http://127.0.0.1:3093/"
    assert not any("logout" in u or "evil" in u for u in fetched)


# --- auth endpoints (CC-SESS-0611, NFR-FUZZ-safe) --------------------------------------

def _manager(*endpoints):
    from fuzzlab.session.manager import SessionManager
    mgr = SessionManager.__new__(SessionManager)
    mgr._auth_endpoints = {}
    mgr._record_auth_endpoints(*endpoints)
    return mgr


def test_a_routed_login_is_its_own_page_only():
    mgr = _manager("http://127.0.0.1:3093/index.php?page=login.php",
                   "http://127.0.0.1:3093/logout")
    assert mgr.is_auth_endpoint("http://127.0.0.1:3093/index.php?page=login.php")
    assert mgr.is_auth_endpoint(
        "http://127.0.0.1:3093/index.php?username=x&page=login.php")
    assert not mgr.is_auth_endpoint("http://127.0.0.1:3093/index.php?page=user-info.php")
    assert not mgr.is_auth_endpoint("http://127.0.0.1:3093/index.php")
    assert mgr.is_auth_endpoint("http://127.0.0.1:3093/logout?x=1")


def test_a_plain_auth_endpoint_is_still_compared_by_its_path():
    """Unchanged for every endpoint that is not a front controller's routed page."""
    mgr = _manager("http://127.0.0.1:8092/bWAPP/login.php", "http://127.0.0.1:3000/login?next=/a")
    assert mgr.is_auth_endpoint("http://127.0.0.1:8092/bWAPP/login.php?x=1")
    assert mgr.is_auth_endpoint("http://127.0.0.1:3000/login")
    assert not mgr.is_auth_endpoint("http://127.0.0.1:3001/login")
