"""DVWA as an external lab (CC-LAB-0430..0433, FR-LAB-430..433): the compose fixture's
safety properties, the bootstrap (database, accounts, security level) on a fake client,
and DVWA's state-changing routes judged by the crawl gates (PA-0114 / PA-0301).

The route table follows `tests/test_destructive_routes_external_labs.py`: each row names
the gate that must stop the route and computes that gate's verdict; a route no gate
refuses is a ``residual`` with the reason it is accepted, its verdict pinned to None so
the row is revisited the day a rule starts refusing it. Enumerated from DVWA's source at
upstream commit 502ac150 (the pinned image's tree) before the first crawl.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace as NS

import pytest
import yaml

from fuzzlab.core.urls import destructive_reason, text_destructive_reason
from fuzzlab.lab_fixtures import external as ext
from fuzzlab.tools.formnav import settings_word
from fuzzlab.tools.store_adapter import form_skip_reason, request_refusal
from tests.test_destructive_routes_external_labs import Route, _form

REPO = Path(__file__).resolve().parent.parent
COMPOSE = REPO / "lab" / "external" / "dvwa" / "compose.yaml"
DVWA = "http://127.0.0.1:3097"


# --- 1. the compose fixture -----------------------------------------------------------

def _doc():
    return yaml.safe_load(COMPOSE.read_text("utf-8"))


def test_the_dvwa_database_is_unpublished_on_an_internal_network():
    doc = _doc()
    db = doc["services"]["db"]
    assert "ports" not in db and db["networks"] == ["dvwa-db"]
    assert doc["networks"]["dvwa-db"]["internal"] is True
    assert db["tmpfs"] == ["/var/lib/mysql"]          # reset = restart + setup.php


def test_the_dvwa_web_tier_is_contained_and_starts_every_session_at_low():
    web = _doc()["services"]["web"]
    assert web["ports"] == ["127.0.0.1:${DVWA_PORT:-3097}:80"]
    assert web["dns"] == ["127.0.0.1"]                # no name resolution (outside fetches)
    assert web["cap_drop"] == ["ALL"] and "no-new-privileges:true" in web["security_opt"]
    assert web["pids_limit"] and web["mem_limit"]
    # the level a cookie-less session gets (dvwaPage.inc.php:22); the bootstrap checks it
    assert web["environment"]["DEFAULT_SECURITY_LEVEL"] == ext.DVWA_LEVEL == "low"


def test_the_dvwa_images_are_the_pinned_constants():
    doc = _doc()
    assert doc["services"]["web"]["image"] == ext.DVWA_IMAGE
    assert doc["services"]["db"]["image"] == ext.DVWA_MARIADB_IMAGE
    assert {ext.DVWA_IMAGE, ext.DVWA_MARIADB_IMAGE} <= ext.PINNED_IMAGES
    assert all("@sha256:" in ref for ref in (ext.DVWA_IMAGE, ext.DVWA_MARIADB_IMAGE))


def test_dvwa_uses_two_of_upstreams_seeded_accounts():
    meta = ext.LAB_META["dvwa"]
    assert [(a.identity, a.default_username) for a in meta.accounts()] == [
        ("dvwa-user", "admin"), ("dvwa-peer", "gordonb")]
    assert not meta.may_generate_password             # upstream's seed, never registered
    assert ext._BOOTSTRAPS["dvwa"] is ext.bootstrap_dvwa


# --- 2. the bootstrap on a fake DVWA ----------------------------------------------------

class _Resp:
    def __init__(self, status, text="", location="", cookies=None):
        self.status_code, self.text = status, text
        self.headers = {"Location": location} if location else {}
        self.cookies = cookies or {}

    def close(self):
        pass


class _FakeDvwa:
    """DVWA's login, setup and security pages as the bootstrap sees them (fields and
    messages as upstream's login.php, setup.php, security.php and MySQL.php write
    them). ``seeded`` is whether the users table exists; ``passwords`` its rows."""
    origin = DVWA
    SEED = {"admin": "password", "gordonb": "abc123"}

    def __init__(self, *, seeded=True, default_level="low", applies_level=True,
                 passwords=None):
        self.seeded, self.default_level, self.applies_level = seeded, default_level, \
            applies_level
        self.passwords = dict(passwords or self.SEED)
        self.who, self.resets, self.sent = None, 0, []
        self.session = NS(cookies={})

    def _form(self, token="0123abcd"):
        return _Resp(200, f"<form><input type='hidden' name='user_token' value='{token}' />")

    def request(self, method, path, *, anonymous=False, data=None, **kw):
        self.sent.append((method, path, dict(data or {})))
        if path == "/login.php" and method == "GET":
            if anonymous:
                return _Resp(200, "login", cookies={"security": self.default_level})
            if not self.seeded:
                return _Resp(302, location="setup.php")
            self.session.cookies.setdefault("security", self.default_level)
            return self._form()
        if path == "/login.php" and method == "POST":
            assert data["user_token"] == "0123abcd" and data["Login"] == "Login"
            ok = self.passwords.get(data["username"]) == data["password"]
            self.who = data["username"] if ok else None
            return _Resp(302, location="index.php" if ok else "login.php")
        if path == "/setup.php" and method == "GET":
            msg = "<div class=\"message\">Data inserted into 'users' table.</div>" \
                if self.resets else ""
            return _Resp(200, self._form().text + msg)
        if path == "/setup.php" and method == "POST":
            assert data == {"create_db": "Create / Reset Database", "user_token": "0123abcd"}
            self.seeded, self.passwords, self.resets = True, dict(self.SEED), self.resets + 1
            return _Resp(302, location="setup.php")
        if path == "/security.php" and method == "GET":
            level = self.session.cookies.get("security")
            return _Resp(200, self._form().text
                         + f"<p>Security level is currently: <em>{level}</em>.<p>")
        if path == "/security.php" and method == "POST":
            assert data["seclev_submit"] == "Submit" and data["user_token"] == "0123abcd"
            if self.applies_level:
                self.session.cookies["security"] = data["security"]
            return _Resp(302, location="security.php")
        if path == "/index.php":
            if anonymous or self.who is None:
                return _Resp(302, location="login.php")
            return _Resp(200, "home")
        raise AssertionError((method, path))


def _boot(fake, user="admin", password="password"):
    return ext.bootstrap_dvwa(fake, NS(username=user, password=password), deadline=1,
                              clock=lambda: 0.0, sleep=lambda s: None)


def test_the_bootstrap_builds_a_missing_database_then_logs_in_at_low():
    fake = _FakeDvwa(seeded=False)
    notes = _boot(fake)
    assert fake.resets == 1 and fake.who == "admin"
    assert notes == ["database created / reset (setup.php)",
                     "security level low (default and set)", "login verified"]
    assert ("POST", "/security.php", {"security": "low", "seclev_submit": "Submit",
                                      "user_token": "0123abcd"}) in fake.sent


def test_the_bootstrap_leaves_a_working_database_alone():
    fake = _FakeDvwa()
    assert _boot(fake, "gordonb", "abc123")[0] == "security level low (default and set)"
    assert fake.resets == 0


def test_the_bootstrap_resets_a_changed_seeded_password():
    """A CSRF-page probe changes the session user's password on a GET; the reset
    restores upstream's seed."""
    fake = _FakeDvwa(passwords={"admin": "changed-by-a-probe", "gordonb": "abc123"})
    _boot(fake)
    assert fake.resets == 1 and fake.passwords["admin"] == "password"


def test_the_bootstrap_refuses_a_password_the_seed_does_not_have():
    with pytest.raises(ext.ExternalLabError, match="failed after a database reset"):
        _boot(_FakeDvwa(), "admin", "not-the-seed")


@pytest.mark.parametrize("fake, why", [
    (_FakeDvwa(default_level="impossible"), "default security level is 'impossible'"),
    (_FakeDvwa(applies_level=False, default_level="low"), None),
])
def test_the_bootstrap_checks_the_level_it_relies_on(fake, why):
    if why:
        with pytest.raises(ext.ExternalLabError, match=why):
            _boot(fake)
    else:
        # the default is low already, so a security.php that ignores the POST still
        # reads back low: the check is on the value, not on the request
        assert "security level low (default and set)" in _boot(fake)


def test_the_bootstrap_fails_when_the_level_cannot_be_set():
    fake = _FakeDvwa()
    fake.session.cookies["security"] = "medium"       # a session carrying another level
    fake.applies_level = False
    with pytest.raises(ext.ExternalLabError, match="did not set the security level"):
        _boot(fake)


# --- 3. PA-0114: DVWA's state switches against the crawl gates --------------------------

def _d(path: str) -> str:
    return DVWA + path


def _d_form(markup: str, page: str):
    return lambda: form_skip_reason(_form(markup, _d(page)))


#: The real forms as the pinned image serves them (fetched live, token values replaced).
DV_SECURITY = """<form action="#" method="POST"><select name="security">
  <option value="low">Low</option><option value="medium">Medium</option>
  <option value="high">High</option><option value="impossible">Impossible</option></select>
  <input type="submit" value="Submit" name="seclev_submit">
  <input type='hidden' name='user_token' value='t' /></form>"""            # security.php:76
DV_SETUP = """<form action="#" method="post">
  <input name="create_db" type="submit" value="Create / Reset Database">
  <input type='hidden' name='user_token' value='t' /></form>"""              # setup.php
DV_CSRF = """<form action="#" method="GET">
  <input type="password" AUTOCOMPLETE="off" name="password_new">
  <input type="password" AUTOCOMPLETE="off" name="password_conf">
  <input type="submit" value="Change" name="Change"></form>"""      # csrf/index.php
DV_GUESTBOOK = """<form method="post" name="guestform">
  <input name="txtName" type="text" size="30" maxlength="10">
  <textarea name="mtxMessage" cols="50" rows="3" maxlength="50"></textarea>
  <input name="btnSign" type="submit" value="Sign Guestbook">
  <input name="btnClear" type="submit" value="Clear Guestbook"></form>"""  # xss_s/index.php
DV_UPLOAD = """<form enctype="multipart/form-data" action="#" method="POST">
  <input type="hidden" name="MAX_FILE_SIZE" value="100000" />
  <input name="uploaded" type="file" /><input type="submit" name="Upload" value="Upload" />
  </form>"""                                                                  # upload/index.php
DV_WEAK_ID = """<form method="post"><input type="submit" value="Generate" /></form>"""


DVWA_ROUTES = [
    Route("dvwa", "GET", _d("/setup.php"), "the menu link; its form drops the database",
          "visit", lambda: destructive_reason(_d("/setup.php")), "refused"),
    Route("dvwa", "POST", _d("/setup.php"), "Create / Reset Database: DROP DATABASE, "
          "re-seed (MySQL.php)", "form", _d_form(DV_SETUP, "/setup.php"), "refused"),
    Route("dvwa", "GET", _d("/logout.php"), "ends the session", "visit",
          lambda: destructive_reason(_d("/logout.php")), "refused"),
    Route("dvwa", "POST", _d("/security.php"),
          "sets the `security` cookie (the level the answer key assumes)", "form",
          _d_form(DV_SECURITY, "/security.php"), "refused"),
    Route("dvwa", "GET", _d("/vulnerabilities/csrf/"),
          "UPDATE users SET password for the session user on a GET (csrf/source/low.php)",
          "form", _d_form(DV_CSRF, "/vulnerabilities/csrf/"), "refused"),
    Route("dvwa", "DELETE", _d("/vulnerabilities/api/v2/user/1"),
          "the API module's user delete (UserController.php:280)", "request",
          lambda: request_refusal("DELETE", _d("/vulnerabilities/api/v2/user/1")),
          "refused"),
    Route("dvwa", "PUT", _d("/vulnerabilities/api/v2/user/1"), "the API's user update",
          "request", lambda: request_refusal("PUT", _d("/vulnerabilities/api/v2/user/1")),
          "refused"),
    Route("dvwa", "POST", _d("/vulnerabilities/upload/"), "writes the uploaded file to "
          "hackable/uploads/", "form", _d_form(DV_UPLOAD, "/vulnerabilities/upload/"),
          "refused"),
    # residuals
    Route("dvwa", "GET", _d("/security.php"), "renders the level form only", "visit",
          lambda: destructive_reason(_d("/security.php")),
          "residual: a visit changes nothing; the form is refused by the form gate (row "
          "above), and the level is a client cookie whose default is low for every new "
          "session (compose DEFAULT_SECURITY_LEVEL; the bootstrap checks it)"),
    Route("dvwa", "GET", _d("/vulnerabilities/csrf/?password_new=x&password_conf=x&"
                            "Change=Change"),
          "the same password change as a bare URL", "visit",
          lambda: destructive_reason(_d("/vulnerabilities/csrf/?password_new=x&"
                                        "password_conf=x&Change=Change")),
          "residual: no page links it (the form is refused); a run that changes the "
          "password is undone by the bootstrap, which resets the seed when the login "
          "fails (FR-LAB-431), and `password_new` is a credential name never fuzzed"),
    Route("dvwa", "POST", _d("/vulnerabilities/xss_s/"),
          "adds a guestbook row (btnClear, a second submitter, deletes them)", "form",
          _d_form(DV_GUESTBOOK, "/vulnerabilities/xss_s/"),
          "residual: row creation is the stored-XSS cell; btnClear is not the default "
          "submitter and is never sent"),
    Route("dvwa", "POST", _d("/vulnerabilities/weak_id/"),
          "sets a dvwaSession cookie (a session counter)", "form",
          _d_form(DV_WEAK_ID, "/vulnerabilities/weak_id/"),
          "residual: session-scoped counter, no lab state"),
    Route("dvwa", "POST", _d("/vulnerabilities/authbypass/change_user_details.php"),
          "UPDATE users SET first/last name from a JSON body (the page's own script)",
          "request", lambda: request_refusal(
              "POST", _d("/vulnerabilities/authbypass/change_user_details.php")),
          "residual: names only, restored by setup.php; not captured by this crawl (the "
          "page's script sends it only on a click)"),
    Route("dvwa", "POST", _d("/vulnerabilities/exec/"), "runs ping on the input (RCE demo)",
          "visit", lambda: destructive_reason(_d("/vulnerabilities/exec/")),
          "residual: the route is the vulnerability; damage is bounded by the payloads and "
          "the fixture container"),
]


@pytest.mark.parametrize("route", DVWA_ROUTES, ids=lambda r: f"{r.method}:{r.url}")
def test_each_dvwa_state_switch_gets_its_gates_actual_verdict(route):
    verdict = route.verdict()
    if route.expect == "refused":
        assert verdict is not None, f"{route.url}: {route.gate} gate let it through"
    else:
        assert route.expect.startswith("residual: ") and len(route.expect) > 20
        assert verdict is None, (f"{route.url} is now refused ({verdict!r}): move it "
                                 "from the residuals to 'refused'")


def test_the_dvwa_residuals_hold_for_the_reason_stated():
    from fuzzlab.harness.auto import _credential_name
    sent = {n for n, _v in _form(DV_GUESTBOOK, _d("/vulnerabilities/xss_s/"))["entries"]}
    assert "btnSign" in sent and "btnClear" not in sent
    assert text_destructive_reason("Clear Guestbook")            # had it been the submitter
    assert _credential_name("password_new")
    assert settings_word("security") == "security"               # the level form's select


def test_every_new_dvwa_session_starts_at_the_compose_default_level():
    """The level is the `security` cookie, not server state (dvwaPage.inc.php:22,
    dvwaSecurityLevelSet): a crawler that changed it changed only its own jar. Every new
    session gets the compose default, which the bootstrap checks (FR-LAB-431)."""
    web = _doc()["services"]["web"]
    assert web["environment"]["DEFAULT_SECURITY_LEVEL"] == "low"
