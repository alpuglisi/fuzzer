"""BUG-0110: forms are serialised as a browser's entry list, not attribute by attribute.

Found live against a loopback bWAPP: its login form needs the submit button's
``form=submit`` and a ``<select>``'s default option, and the detector sent neither.
Every rule in ``fuzzlab.core.forms.RULES`` has a fixture below; a rule without one fails
``test_every_rule_has_a_fixture`` (PA-0111).
"""

import pytest
from bs4 import BeautifulSoup

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.core.forms import RULES, FormEntries, default_value, form_entries
from fuzzlab.session import detect
from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager
from fuzzlab.tools.fetcher import PageContext, rule_serialized_tokens
from tests.test_credentials import FakeBackend

# Captured shape of bWAPP's login.php (a real third-party target, not our own lab).
BWAPP_LOGIN = """
<form action="/bWAPP/login.php" method="POST">
  <p><label for="login">Login:</label><br>
  <input type="text" id="login" name="login" size="20" autocomplete="off"></p>
  <p><label for="password">Password:</label><br>
  <input type="password" id="password" name="password" size="20" autocomplete="off"></p>
  <p><label for="security_level">Set the security level:</label><br>
  <select name="security_level">
    <option value="0">low</option>
    <option value="1">medium</option>
    <option value="2">high</option>
  </select></p>
  <button type="submit" name="form" value="submit">Login</button>
</form>
"""

#: rule id -> (html of a document whose first <form> is serialised, expected entries)
FIXTURES = {
    "skip-unnamed": ('<form><input value="x"><input name="" value="y">'
                     '<input name="a" value="1"></form>', [("a", "1")]),
    "skip-disabled": ('<form><input name="off" value="1" disabled>'
                      '<input name="on" value="2"></form>', [("on", "2")]),
    "skip-disabled-fieldset": (
        '<form><fieldset disabled><legend><input name="in_legend" value="kept"></legend>'
        '<input name="in_set" value="dropped"></fieldset></form>',
        [("in_legend", "kept")]),
    "readonly-sent": ('<form><input name="r" value="v" readonly></form>', [("r", "v")]),
    "form-owner": (
        '<form id="f"><input name="inside" value="1">'
        '<input name="elsewhere" value="2" form="other"></form>'
        '<form id="other"></form>'
        '<button form="f" name="go" value="outside">Go</button>',
        [("inside", "1"), ("go", "outside")]),
    "submitter-first-in-tree-order": (
        '<form><button name="a" value="1" disabled>A</button>'
        '<button name="b" value="2">B</button>'
        '<input type="submit" name="c" value="3"><button name="d" value="4">D</button>'
        '</form>',
        [("b", "2")]),
    "button-default-type-submit": (
        '<form><button type="BOGUS" name="x" value="1">X</button></form>', [("x", "1")]),
    "non-submitter-buttons-skipped": (
        '<form><input type="button" name="b" value="b"><input type="reset" name="r">'
        '<button type="Button" name="p" value="p">p</button>'
        '<button type="reset" name="q">q</button></form>', []),
    "image-submitter-coordinates": (
        '<form><input type="image" src="x.png"></form>', [("x", "0"), ("y", "0")]),
    "checkable-only-when-checked": (
        '<form><input type="checkbox" name="news" value="yes">'
        '<input type="radio" name="role" value="user">'
        '<input type="radio" name="role" value="admin" checked></form>',
        [("role", "admin")]),
    "checkable-default-on": (
        '<form><input type="checkbox" name="remember" checked>'
        '<input type="checkbox" name="empty" value="" checked></form>',
        [("remember", "on"), ("empty", "")]),
    "select-each-selected-option": (
        '<form><select name="m" multiple><option value="1" selected>1</option>'
        '<option value="2">2</option><option value="3" selected>3</option></select>'
        '<select name="none" multiple><option value="z">z</option></select></form>',
        [("m", "1"), ("m", "3")]),
    "select-selected-disabled-not-sent": (
        '<form><select name="c"><option disabled selected>Choose</option>'
        '<option value="1">A</option></select>'
        '<select name="m" multiple><option value="x" selected disabled>x</option>'
        '<option value="y" selected>y</option></select></form>',
        [("m", "y")]),
    "select-display-default": (
        '<form><select name="a"><option disabled value="x">x</option>'
        '<option value="y">y</option></select>'
        '<select name="lb" size="3"><option value="n">n</option></select>'
        '<select name="empty"></select></form>',
        [("a", "y")]),
    "option-disabled-by-optgroup": (
        '<form><select name="g"><optgroup disabled><option value="no">no</option>'
        '</optgroup><option value="yes">yes</option></select></form>',
        [("g", "yes")]),
    "option-value-or-text": (
        '<form><select name="t"><option>  Plain   text </option></select>'
        '<select name="e"><option value="" selected>blank</option></select></form>',
        [("t", "Plain text"), ("e", "")]),
    "textarea-text": ('<form><textarea name="note">\nhello</textarea></form>',
                      [("note", "hello")]),
    "file-not-sent-as-text": ('<form><input type="file" name="upload"></form>', []),
    "duplicates-kept-in-order": (
        '<form><input type="hidden" name="remember" value="0">'
        '<input type="checkbox" name="remember" value="1" checked>'
        '<input name="tag[]" value="a"><input name="tag[]" value="b"></form>',
        [("remember", "0"), ("remember", "1"), ("tag[]", "a"), ("tag[]", "b")]),
}


def _form(html):
    return BeautifulSoup(html, "html.parser").find("form")


def test_every_rule_has_a_fixture():
    assert set(FIXTURES) == set(RULES)


@pytest.mark.parametrize("rule", sorted(RULES))
def test_rule_fixture(rule):
    html, expected = FIXTURES[rule]
    assert list(form_entries(_form(html))) == expected


def test_bwapp_login_form_posts_what_a_browser_posts():
    form = detect.find_login_form(BWAPP_LOGIN, "http://127.0.0.1:8090/bWAPP/login.php")
    assert form.username_field == "login" and form.password_field == "password"
    assert list(form.fill("bee", "bug")) == [("login", "bee"), ("password", "bug"),
                                             ("security_level", "0"), ("form", "submit")]


def test_fill_replaces_credentials_in_place_and_keeps_duplicates():
    html = ('<form><input type="hidden" name="t" value="csrf"><input name="email">'
            '<input type="password" name="pw"><input type="hidden" name="t" value="2">'
            '</form>')
    form = detect.find_login_form(html, "http://h/")
    filled = form.fill("me@x", "s3cret")
    assert list(filled) == [("t", "csrf"), ("email", "me@x"), ("pw", "s3cret"), ("t", "2")]
    assert isinstance(filled, FormEntries) and filled.get("t") == "2"
    assert list(form.fields) == [("t", "csrf"), ("email", ""), ("pw", ""), ("t", "2")]


def test_a_disabled_password_field_is_not_a_login_form():
    html = '<form><input name="u"><input type="password" name="p" disabled></form>'
    assert detect.find_login_form(html, "http://h/") is None


def test_submitter_overrides_are_reported():
    html = ('<form action="/login"><input name="u"><input type="password" name="p">'
            '<button formaction="https://elsewhere.example/collect" formmethod="get">'
            'Go</button></form>')
    form = detect.find_login_form(html, "http://h/")
    assert form.submitter_overrides == ("formaction", "formmethod")


def test_crawler_reports_a_controls_default_value():
    page = """<html><body><form action="/x.php" method="get">
      <select name="bug"><option value="1">a</option><option value="7" selected>b</option></select>
      <textarea name="t">body</textarea></form></body></html>"""
    ctx = PageContext("http://h/x.php", "test", 200, "text/html", page, [])
    assert {f["name"]: f["value"] for f in ctx.fields} == {"bug": "7", "t": "body"}
    soup = BeautifulSoup('<input type="checkbox" name="c">', "html.parser")
    assert default_value(soup.find("input")) == "on"


def test_crawler_value_rules_now_see_a_textareas_content():
    """Behaviour change (CC-CRAWL-0011): value-based rules used to see "" for a textarea
    or select; they now see what the control actually holds."""
    token = 'O:4:"User":1:{s:4:"role";s:5:"admin";}'
    page = (f'<html><body><form><textarea name="state">{token}</textarea>'
            '</form></body></html>')
    ctx = PageContext("http://h/x.php", "test", 200, "text/html", page, [])
    hits = []
    rule_serialized_tokens(ctx, lambda target, context: hits.append(context))
    assert any("field state" in h for h in hits)


class _BwappFetcher:
    """bWAPP's login.php: it processes the POST only if the submit button's
    ``form`` field is present, and needs a ``security_level``."""

    def __init__(self, page=BWAPP_LOGIN):
        self.page = page
        self.logged_in = False
        self.posts = []
        self._cookies = {"PHPSESSID": "anon"}

    def get(self, url, headers=None, allow_redirects=True):
        if url.endswith("/login.php"):
            return FetchResponse(200, {}, self.page)
        if self.logged_in:
            return FetchResponse(200, {}, "<html>Welcome Bee</html>")
        return FetchResponse(302, {"Location": "/bWAPP/login.php"}, "")

    def post(self, url, data=None, headers=None):
        self.posts.append((url, data))
        data = dict(data or [])
        if (data.get("form") == "submit" and data.get("security_level") in ("0", "1", "2")
                and data.get("login") == "bee" and data.get("password") == "bug"):
            self.logged_in = True
            self._cookies = {"PHPSESSID": "authed"}
            return FetchResponse(302, {"Location": "portal.php"}, "")
        return FetchResponse(200, {}, self.page)

    def cookies(self):
        return dict(self._cookies)


def _manager(fetcher):
    store = CredentialStore(backend=FakeBackend())
    store.set("127.0.0.1", "user", "bee", "bug")
    return SessionManager(store, scope_hosts=["127.0.0.1"], fetch_factory=lambda: fetcher)


def test_session_manager_logs_into_a_bwapp_shaped_target():
    fetcher = _BwappFetcher()
    state = _manager(fetcher).ensure("127.0.0.1", "user", "http://127.0.0.1:8090/bWAPP/")
    assert state.valid and state.cookies.get("PHPSESSID") == "authed"


def test_a_submitter_formaction_makes_no_credential_request():
    page = BWAPP_LOGIN.replace(
        '<button type="submit"',
        '<button formaction="https://elsewhere.example/collect" type="submit"')
    fetcher = _BwappFetcher(page)
    with pytest.raises(SessionAuthError, match="formaction"):
        _manager(fetcher).ensure("127.0.0.1", "user", "http://127.0.0.1:8090/bWAPP/")
    assert fetcher.posts == []
