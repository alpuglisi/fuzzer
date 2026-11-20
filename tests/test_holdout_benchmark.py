"""The held-out benchmark's own tests (lab/HOLDOUT.md, FR-LAB-420..423, FR-CORE-680..).

This is the ONLY test file that may name a held-out lab (lab/HOLDOUT.md rule 4). It
holds: the guard that enforces that rule, the table parser's checks, the benchmark
script's offline checks (``scripts/holdout_score.py`` against fakes: nothing here
sends traffic), and each held-out lab fixture's unit tests (its bootstrap against a fake
client). No test here runs a held-out lab or reads its answer key for anything but
structure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fuzzlab.lab_fixtures import heldout

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
THIS = Path(__file__).resolve()


# --- the rule's guard (lab/HOLDOUT.md rule 4) -----------------------------------------

def held_out_name_offenders(root: Path, labs, allowed: set[Path]) -> list[str]:
    """``file:line`` of every held-out name in a text file under ``root``, except
    ``allowed``."""
    pat = heldout.name_pattern(labs)
    out = []
    for f in sorted(root.rglob("*")):
        if not f.is_file() or "__pycache__" in f.parts or f.resolve() in allowed:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue                      # binary data: no name a reader could follow
        for n, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                out.append(f"{f.relative_to(root)}:{n}")
    return out


def test_the_holdout_table_lists_the_held_out_labs():
    labs = heldout.held_out_labs()
    assert labs, "lab/HOLDOUT.md lists no held-out lab"
    for lab in labs:
        assert lab.upstream and lab.stack and lab.names


def test_no_other_test_file_names_a_held_out_lab():
    """Only this file may name a held-out lab (lab/HOLDOUT.md rule 4)."""
    labs = heldout.held_out_labs()
    assert held_out_name_offenders(TESTS, labs, {THIS}) == []


def test_the_guard_flags_a_synthetic_offender(tmp_path):
    labs = heldout.parse_holdout_table(
        "## Held-out labs\n\n| Lab | Upstream | Stack | Names |\n| --- | --- | --- | --- |\n"
        "| acme-lab | someone/acme | Go | acmelab, acme-lab |\n")
    (tmp_path / "test_tuned.py").write_text("LAB = 'ACMELAB'\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "key.json").write_text('{"dir": "lab/ground-truth-acme-lab"}\n')
    (tmp_path / "test_clean.py").write_text("x = 'acmelabs and xacmelab'\n")
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe acmelab")
    assert held_out_name_offenders(tmp_path, labs, set()) == [
        "data/key.json:1", "test_tuned.py:1"]
    assert held_out_name_offenders(tmp_path, labs, {(tmp_path / "test_tuned.py").resolve(),
                                                    (tmp_path / "data/key.json").resolve()}
                                   ) == []


@pytest.mark.parametrize("text", [
    "no section here",
    "## Held-out labs\n\n(none)\n",
    "## Held-out labs\n| a | b | c | d |\n| - | - | - | - |\n| Bad Name | u | s | x1x |\n",
    "## Held-out labs\n| a | b | c | d |\n| - | - | - | - |\n| ok | u | s |  |\n",
    "## Held-out labs\n| a | b | c | d |\n| - | - | - | - |\n| ok | u | s | ok1 |\n"
    "| ok | u | s | ok2 |\n",
    "## Held-out labs\n| a | b | c |\n| - | - | - |\n| ok | u | s |\n",
])
def test_a_malformed_holdout_table_fails_closed(text):
    with pytest.raises(heldout.HoldoutTableError):
        heldout.parse_holdout_table(text)


def test_every_held_out_lab_has_its_fixture_and_answer_key():
    """The benchmark can run each listed lab: a compose file, a registered LabMeta and an
    answer key at ``lab/ground-truth-<lab>/`` (where PA-0660's guard reads it)."""
    from fuzzlab.lab_fixtures import external as ext
    from fuzzlab.labels import contract
    for lab in heldout.held_out_labs():
        assert (REPO / "lab" / "external" / lab.name / "compose.yaml").is_file(), lab.name
        assert lab.name in ext.LAB_META, lab.name
        gt = contract.load(REPO / "lab" / f"ground-truth-{lab.name}")
        assert gt.positives() and gt.negatives(), lab.name


# --- scripts/holdout_score.py (offline) ------------------------------------------------


# --- held-out lab fixture: vampi --------------------------------------------------------

class _VampiResp:
    def __init__(self, status, js=None, text=None):
        self.status_code, self._js = status, js
        self.text = text if text is not None else json.dumps(js)
        self.headers = {}

    def json(self):
        if self._js is None:
            raise ValueError("no json")
        return self._js

    def close(self):
        pass


class _VampiApp:
    """VAmPI's routes the bootstrap uses, as upstream f16052dc answers them (measured on
    the loopback lab): tables only after /createdb, a failed login 200 with status fail,
    /me 401 without a bearer token, one book title per database."""

    def __init__(self, tables=False, me_anon=401, register_admin=False):
        self.tables, self.me_anon, self.register_admin = tables, me_anon, register_admin
        self.users, self.books, self.calls, self.registered = {}, {}, [], []

    def _who(self, kw):
        auth = (kw.get("headers") or {}).get("Authorization", "")
        return auth[len("Bearer tok-"):] if auth.startswith("Bearer tok-") else None

    def handle(self, method, path, kw):
        self.calls.append((method, path))
        body = kw.get("json") or {}
        if path == "/":
            return _VampiResp(200, {"message": "VAmPI the Vulnerable API"})
        if path == "/createdb":
            self.tables, self.users, self.books = True, {}, {}
            return _VampiResp(200, {"message": "Database populated."})
        if not self.tables:
            return _VampiResp(500, text="no such table: users")
        if path == "/users/v1":
            return _VampiResp(200, {"users": []})
        if path == "/users/v1/login":
            user = self.users.get(body["username"])
            if user and user["password"] == body["password"]:
                return _VampiResp(200, {"status": "success",
                                        "auth_token": "tok-" + body["username"]})
            return _VampiResp(200, {"status": "fail", "message": "Username does not exist"})
        if path == "/users/v1/register":
            if body["username"] in self.users:
                return _VampiResp(200, {"status": "fail", "message": "User already exists."})
            self.registered.append(dict(body))
            self.users[body["username"]] = dict(body, admin=self.register_admin)
            return _VampiResp(200, {"status": "success", "message":
                                    "Successfully registered. Login to receive a token."})
        who = self._who(kw)
        if path == "/me":
            if who is None:
                return _VampiResp(self.me_anon, {"status": "fail"})
            return _VampiResp(200, {"data": {"username": who,
                                             "admin": self.users[who]["admin"]}})
        if who is None:
            return _VampiResp(401, {"status": "fail"})
        if method == "POST" and path == "/books/v1":
            if body["book_title"] in self.books:
                return _VampiResp(400, {"status": "fail", "message": "Book Already exists!"})
            self.books[body["book_title"]] = who
            return _VampiResp(200, {"status": "success"})
        if path.startswith("/books/v1/"):
            owner = self.books.get(path[len("/books/v1/"):])
            return _VampiResp(200, {"owner": owner}) if owner else _VampiResp(404, {})
        raise AssertionError((method, path))


class _VampiClient:
    origin = "http://127.0.0.1:3101"

    def __init__(self, app):
        self.app = app

    def request(self, method, path, *, anonymous=False, **kw):
        return self.app.handle(method, path, kw)


def _vampi_cred(user="fuzzlab_user", password="pw-1"):
    from types import SimpleNamespace as NS
    return NS(username=user, password=password)


def test_the_vampi_bootstrap_creates_the_tables_registers_and_verifies_by_differential():
    from fuzzlab.lab_fixtures import external as ext
    app = _VampiApp()
    notes = ext.bootstrap_vampi(_VampiClient(app), _vampi_cred(), deadline=1,
                                sleep=lambda s: None)
    assert notes == ["database created", "account registered", "login verified",
                     "book added"]
    assert app.users["fuzzlab_user"]["admin"] is False
    assert [sorted(b) for b in app.registered] == [["email", "password", "username"]]
    assert app.books == {"fuzzlab_user-book": "fuzzlab_user"}
    assert ext.vampi_account_attributes(_VampiClient(app), _vampi_cred()) == \
        {"book_title": "fuzzlab_user-book", "username": "fuzzlab_user"}


def test_the_vampi_bootstrap_never_recreates_a_populated_database():
    """/createdb drops every table: a second run (the accounts exist) must not call it."""
    from fuzzlab.lab_fixtures import external as ext
    app = _VampiApp()
    ext.bootstrap_vampi(_VampiClient(app), _vampi_cred(), deadline=1, sleep=lambda s: None)
    app.calls.clear()
    notes = ext.bootstrap_vampi(_VampiClient(app), _vampi_cred(), deadline=1,
                                sleep=lambda s: None)
    assert notes == ["login verified"]
    assert ("GET", "/createdb") not in app.calls
    assert ("POST", "/users/v1/register") not in app.calls


@pytest.mark.parametrize("app, cred, match", [
    (_VampiApp(me_anon=200), _vampi_cred(), "/me: 200 anonymous"),
    (_VampiApp(register_admin=True), _vampi_cred(), "not an admin"),
], ids=["no-differential", "admin-account"])
def test_the_vampi_bootstrap_refuses_an_unverified_login(app, cred, match):
    from fuzzlab.lab_fixtures import external as ext
    with pytest.raises(ext.ExternalLabError, match=match):
        ext.bootstrap_vampi(_VampiClient(app), cred, deadline=1, sleep=lambda s: None)


def test_the_vampi_bootstrap_with_a_stale_password_says_reset():
    from fuzzlab.lab_fixtures import external as ext
    app = _VampiApp(tables=True)
    app.users["fuzzlab_user"] = {"password": "other", "admin": False}
    with pytest.raises(ext.ExternalLabError, match="reset vampi"):
        ext.bootstrap_vampi(_VampiClient(app), _vampi_cred(), deadline=1,
                            sleep=lambda s: None)
    with pytest.raises(ext.ExternalLabError, match="own book"):
        app.users["fuzzlab_user"]["password"] = "pw-1"         # login ok, no book
        ext.vampi_account_attributes(_VampiClient(app), _vampi_cred())


def test_the_vampi_bootstrap_stores_both_accounts_with_their_values_only_once_verified():
    """Through `bootstrap`: each account on its own client, a generated password stored
    only after the verified login, and the values the answer key names (FR-LAB-309)."""
    from urllib.parse import urlsplit

    from fuzzlab.lab_fixtures import external as ext
    app = _VampiApp()
    stored, attrs, sessions = {}, {}, []

    class Store:
        def get(self, host, identity):
            return None

        def set(self, host, identity, username, password):
            stored[identity] = (host, username, password)

        def set_attributes(self, host, identity, values):
            attrs[identity] = dict(values)

    class Session:
        def __init__(self):
            self.trust_env, self.proxies, self.headers = True, None, {}
            sessions.append(self)

        def request(self, method, url, **kw):
            assert url.startswith("http://127.0.0.1:3101/") and kw["allow_redirects"] is False
            return app.handle(method, urlsplit(url).path, kw)

    res = ext.bootstrap("vampi", environ={}, keyring_store=Store(), opened_store=Store(),
                        prompt=None, session_factory=Session, deadline=1.0)
    assert res.identity == "vampi-user" and [p.identity for p in res.peers] == ["vampi-peer"]
    assert {i: (h, u) for i, (h, u, _p) in stored.items()} == {
        "vampi-user": ("127.0.0.1", "fuzzlab_user"),
        "vampi-peer": ("127.0.0.1", "fuzzlab_peer")}
    assert stored["vampi-user"][2] != stored["vampi-peer"][2]
    assert attrs == {"vampi-user": {"book_title": "fuzzlab_user-book",
                                    "username": "fuzzlab_user"},
                     "vampi-peer": {"book_title": "fuzzlab_peer-book",
                                    "username": "fuzzlab_peer"}}
    assert all(s.trust_env is False and s.proxies == {} for s in sessions)
    assert app.calls.count(("GET", "/createdb")) == 1           # the peer's run kept it
    assert repr(res).count("pw") == 0 and stored["vampi-user"][2] not in repr(res)


def test_the_vampi_fixture_runs_the_pinned_image_in_vulnerable_mode_on_loopback():
    import yaml

    from fuzzlab.lab_fixtures import external as ext
    doc = yaml.safe_load((REPO / "lab/external/vampi/compose.yaml").read_text("utf-8"))
    svc = doc["services"]["app"]
    assert doc["name"] == "fuzzlab-vampi"
    assert svc["image"] == ext.VAMPI_IMAGE and ext.VAMPI_IMAGE in ext.PINNED_IMAGES
    assert svc["environment"]["vulnerable"] == "1"
    assert svc["ports"] == ["127.0.0.1:${VAMPI_PORT:-3101}:5000"]
    assert svc["read_only"] is True and "/vampi/database" in svc["tmpfs"]
    meta = ext.LAB_META["vampi"]
    assert (meta.default_port, meta.container_port, meta.may_generate_password) == \
        (3101, 5000, True)
    assert [a.identity for a in meta.accounts()] == ["vampi-user", "vampi-peer"]
    gt = json.loads((REPO / "lab/ground-truth-vampi/labels.json").read_text("utf-8"))
    assert "vampi" in gt["target"] and ext.VAMPI_COMMIT[:8] in gt["target"]


# --- end vampi --------------------------------------------------------------------------


# --- held-out lab fixture: dvws-node ----------------------------------------------------


# --- end dvws-node ----------------------------------------------------------------------


# --- held-out lab fixture: railsgoat ----------------------------------------------------


# --- end railsgoat ----------------------------------------------------------------------
