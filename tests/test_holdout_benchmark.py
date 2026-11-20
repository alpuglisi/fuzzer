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

def _score_mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location("holdout_score",
                                                  REPO / "scripts" / "holdout_score.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _case(cid, url, param, vc, vuln=True, reach="crawl,gt"):
    from fuzzlab.labels import contract
    return contract.Case(case_id=cid, url=url, method="GET", param=param, location="query",
                         vuln_class=vc, sink_context="html", expected_vulnerable=vuln,
                         rendering="server", notes=f"[reach: {reach}] [prov: p] x")


def test_the_reach_tag_is_read_from_the_notes():
    m = _score_mod()
    assert m.reach_tag("[reach: crawl,gt] [prov: x] y") == "crawl,gt"
    assert m.reach_tag("[reach: none - websocket only] [prov: x] y") == "none - websocket only"
    assert m.reach_tag("no tag") == "?"


def test_candidate_progress_tells_discovery_from_detection():
    from fuzzlab.core.oracle_status import CHECKED
    m = _score_mod()
    case = _case("X-0001", "/a", "q", "sql-injection")
    from fuzzlab.core.runmode import to_category
    cat = to_category("sql-injection")
    assert m.candidate_progress([], case) == "no candidate"
    assert m.candidate_progress([("/a", "GET", "q", "xss", CHECKED)], case) == (
        "no candidate for the class")
    assert m.candidate_progress([("/a", "GET", "q", cat, "SKIPPED")], case).startswith(
        "candidate not checked")
    assert m.candidate_progress([("/a", "GET", "q", cat, CHECKED)], case) == (
        "checked, not confirmed")


def test_a_lab_row_lists_every_fn_with_its_point_class_and_reach():
    from fuzzlab.harness.scoring import Detection, score
    from fuzzlab.labels import contract
    m = _score_mod()
    cases = [_case("X-0001", "/a", "q", "sql-injection"),
             _case("X-0002", "/b", "id", "sql-injection", reach="gt"),
             _case("X-0003", "/c", "q", "sql-injection", vuln=False)]
    gt = contract.GroundTruth(target="t", cases=cases, points=[])
    report = score([Detection("/a", "GET", "q", "sql-injection"),
                    Detection("/c", "GET", "q", "sql-injection")], gt)
    row = m.lab_row("lab-x", gt, report, [], 42, 1.23)
    assert (row["tp"], row["fp"], row["fn"], row["tn"]) == (1, 1, 1, 0)
    assert row["fns"] == [{"case_id": "X-0002", "url": "/b", "method": "GET", "param": "id",
                           "location": "query", "vuln_class": "sql-injection",
                           "reach": "gt", "progress": "no candidate"}]
    assert row["requests"] == 42 and row["fps"]
    md = m.render_markdown({"fuzzlab_commit": "abc", "detection_base": "e14c925",
                            "detection_identical": True, "generated": "now", "labs": [row]})
    assert "| lab-x | ok | 1 | 1 | 1 | 0 |" in md and "X-0002" in md


def test_the_benchmark_refuses_without_authorized_and_unknown_labs(capsys):
    m = _score_mod()
    assert m.main([]) == 2
    assert "--authorized" in capsys.readouterr().err
    assert m.main(["--lab", "not-held-out", "--authorized"]) == 2


def test_a_benchmark_run_uses_crawl_points_only(tmp_path, monkeypatch):
    """The run's argv: discovery, then `auto --points crawl` with the key only for
    scoring -- never a ground-truth-point run (lab/HOLDOUT.md rule 2)."""
    import types
    m = _score_mod()
    lab = heldout.held_out_labs()[0].name
    calls = []

    def fake_run(self, argv, *, timeout=None, cwd=None):
        calls.append(argv)
        if "disco" in argv:
            out = Path(argv[argv.index("--out") + 1])
            out.mkdir()
            (out / "capture.jsonl").write_text("{}\n")
        if "auto" in argv:
            Path(argv[argv.index("--store") + 1]).write_text("")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    from fuzzlab.harness.scoring import ScoreReport
    from fuzzlab.labels import contract
    gt = contract.GroundTruth(target="t", cases=[_case("X-0001", "/a", "q", "sql-injection")],
                              points=[])
    monkeypatch.setattr(m.Runner, "_run", fake_run)
    monkeypatch.setattr(m, "score_store",
                        lambda store, gt_dir: (gt, ScoreReport(fn=1, missed=["X-0001"]), [], 7))
    row = m.Runner(lab, tmp_path, budget_total=10, timeout=10, disco_deadline=5,
                   log=lambda s: None).run()
    assert row["status"] == "ok" and row["fn"] == 1
    autos = [a for a in calls if a[3:4] == ["auto"]]
    assert len(autos) == 1
    auto = autos[0]
    assert auto[auto.index("--points") + 1] == "crawl"
    assert "--authorized" in auto and "--score" in auto
    assert calls[0][0].endswith("labctl.sh") and calls[0][1:] == ["reset", lab]
    assert not any(a[0].endswith("labctl.sh") and "--authorized" in a and "reset" in a
                   for a in calls)
    assert calls[-1][-2:] == ["down", lab]


def test_a_failed_login_falls_back_to_an_anonymous_crawl_and_run(tmp_path, monkeypatch):
    """A black-box tester whose login fails still crawls and tests anonymously; the row
    says so (lab/HOLDOUT.md: the failed login is recorded, not fixed)."""
    import types
    m = _score_mod()
    lab = next(x.name for x in heldout.held_out_labs()
               if __import__("fuzzlab.lab_fixtures.external", fromlist=["x"]).LAB_META[
                   x.name].identity)
    calls = []

    def fake_run(self, argv, *, timeout=None, cwd=None):
        calls.append(argv)
        rc = 1 if ("--identity" in argv and ("crawl" in argv or "auto" in argv)) else 0
        if "auto" in argv and not rc:
            Path(argv[argv.index("--store") + 1]).write_text("")
        if "disco" in argv:
            Path(argv[argv.index("--out") + 1]).mkdir()
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="")

    from fuzzlab.harness.scoring import ScoreReport
    from fuzzlab.labels import contract
    gt = contract.GroundTruth(target="t", cases=[], points=[])
    monkeypatch.setattr(m.Runner, "_run", fake_run)
    monkeypatch.setattr(m, "score_store", lambda store, gt_dir: (gt, ScoreReport(), [], 0))
    row = m.Runner(lab, tmp_path, budget_total=10, timeout=10, disco_deadline=5,
                   log=lambda s: None).run()
    assert row["status"] == "ok"
    assert row["crawl_auth"].startswith("anonymous") and row["auto_auth"].startswith(
        "anonymous")
    crawls = [a for a in calls if a[3:4] == ["crawl"]]
    autos = [a for a in calls if a[3:4] == ["auto"]]
    assert ["--identity" in a for a in crawls] == [True, False]
    assert ["--identity" in a for a in autos] == [True, False]
    assert all(a[a.index("--points") + 1] == "crawl" for a in autos)


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

class _DvwsResp:
    def __init__(self, status, js=None, text=""):
        self.status_code, self._js, self.text, self.headers = status, js, text, {}

    def json(self):
        if self._js is None:
            raise ValueError("no json")
        return self._js

    def close(self):
        pass


class _DvwsLab:
    """A fake DVWS-node: JSON login answering a Bearer token, registration, and the
    notes list/create that the bootstrap and its account values use."""

    def __init__(self, users=None, anon_notes_status=401):
        self.users = dict(users or {})
        self.notes: list[dict] = []
        self.anon_notes_status = anon_notes_status
        self.log: list[tuple] = []

    def session(self):
        lab = self

        class Session:
            def __init__(self):
                self.headers, self.cookies = {}, {}
                self.trust_env, self.proxies = True, {"http": "http://proxy"}

            def request(self, method, url, **kw):
                from urllib.parse import urlsplit
                lab.log.append((method, url, kw, self))
                return lab.route(method, urlsplit(url).path, kw)
        return Session()

    def _who(self, kw):
        auth = (kw.get("headers") or {}).get("Authorization", "")
        return auth[len("Bearer T-"):] if auth.startswith("Bearer T-") else None

    def route(self, method, path, kw):
        body = kw.get("json") or {}
        if (method, path) == ("GET", "/"):
            return _DvwsResp(200, text="<!doctype html>")
        if (method, path) == ("POST", "/api/v2/login"):
            if body["username"] not in self.users:
                return _DvwsResp(404, {"status": 404})
            if self.users[body["username"]] != body["password"]:
                return _DvwsResp(401, {"status": 401, "error": "Authentication error"})
            return _DvwsResp(200, {"status": 200, "token": "T-" + body["username"]})
        if (method, path) == ("POST", "/api/v2/users"):
            assert set(body) == {"username", "password"}       # never an admin field
            if body["username"] in self.users:
                return _DvwsResp(409, text="already exists")
            self.users[body["username"]] = body["password"]
            return _DvwsResp(201, {"status": 201, "user": body["username"]})
        who = self._who(kw)
        if (method, path) == ("GET", "/api/v2/notes"):
            if who is None:
                return _DvwsResp(self.anon_notes_status, {"error": "Token required"})
            return _DvwsResp(200, [n for n in self.notes if n["user"] == who])
        if (method, path) == ("POST", "/api/v2/notes") and who:
            note = {**body, "user": who, "_id": len(self.notes) + 1}
            self.notes.append(note)
            return _DvwsResp(200, note)
        raise AssertionError(f"unexpected {method} {path}")


class _DvwsStore:
    def __init__(self, creds=None):
        self.creds = dict(creds or {})
        self.sets, self.attrs = [], {}

    def get(self, host, identity):
        if identity not in self.creds:
            return None
        from types import SimpleNamespace
        user, pw = self.creds[identity]
        return SimpleNamespace(username=user, password=pw)

    def set(self, host, identity, username, password):
        self.sets.append((host, identity, username))
        self.creds[identity] = (username, password)

    def set_attributes(self, host, identity, attributes):
        self.attrs[identity] = dict(attributes)


def _dvws_boot(lab, keyring):
    from fuzzlab.lab_fixtures import external as ext
    return ext.bootstrap("dvws-node", environ={}, keyring_store=keyring,
                         opened_store=_DvwsStore(), prompt=None,
                         session_factory=lab.session, deadline=1.0)


def test_the_dvws_bootstrap_registers_both_accounts_and_verifies_by_differential():
    """Each account is registered (username and password only) when the login says it
    does not exist, logged in, verified (/api/v2/notes 200 with the token, 401 without)
    and stored with a generated password; its note_id is a private note of its own."""
    lab, keyring = _DvwsLab(), _DvwsStore()
    res = _dvws_boot(lab, keyring)
    assert (res.identity, [p.identity for p in res.peers]) == ("dvws-user", ["dvws-peer"])
    assert res.credential_source == "generated" and res.stored
    assert res.notes[:2] == ["account registered", "login verified"]
    assert [s[1:] for s in keyring.sets] == [("dvws-user", "fuzzlab_user"),
                                             ("dvws-peer", "fuzzlab_peer")]
    assert set(lab.users) == {"fuzzlab_user", "fuzzlab_peer"}
    assert len({lab.users["fuzzlab_user"], lab.users["fuzzlab_peer"]}) == 2
    assert all(len(pw) >= 24 for pw in lab.users.values())
    assert keyring.attrs == {"dvws-user": {"note_id": "1"}, "dvws-peer": {"note_id": "2"}}
    assert [n["type"] for n in lab.notes] == ["secret", "secret"]
    for method, url, kw, sess in lab.log:
        assert url.startswith("http://127.0.0.1:3102/")
        assert kw["allow_redirects"] is False and kw["timeout"]
        assert sess.trust_env is False and sess.proxies == {}
    # second run: the keyring's credentials log in, nothing is registered or re-created
    res2 = _dvws_boot(lab, keyring)
    assert res2.credential_source == "keyring" and not res2.stored
    assert "account registered" not in res2.notes and len(lab.notes) == 2
    assert keyring.attrs["dvws-user"] == {"note_id": "1"}


def test_the_dvws_bootstrap_stores_nothing_without_a_positive_differential():
    lab, keyring = _DvwsLab(anon_notes_status=200), _DvwsStore()
    from fuzzlab.lab_fixtures import external as ext
    with pytest.raises(ext.ExternalLabError, match="want 401 / 200"):
        _dvws_boot(lab, keyring)
    assert keyring.sets == [] and keyring.attrs == {}


def test_the_dvws_bootstrap_refuses_an_existing_account_with_another_password():
    lab = _DvwsLab(users={"fuzzlab_user": "someone-elses"})
    keyring = _DvwsStore({"dvws-user": ("fuzzlab_user", "ours")})
    from fuzzlab.lab_fixtures import external as ext
    with pytest.raises(ext.ExternalLabError, match="HTTP 401") as err:
        _dvws_boot(lab, keyring)
    assert "ours" not in str(err.value) and keyring.sets == []
    assert ("POST", "/api/v2/users") not in [(m, u.split(":3102")[1]) for m, u, *_ in lab.log]


def test_the_dvws_build_uses_only_the_pinned_base_the_cached_app_and_no_network():
    import yaml
    from fuzzlab.lab_fixtures import external as ext
    lab_dir = REPO / "lab" / "external" / "dvws-node"
    text = (lab_dir / "Dockerfile").read_text("utf-8")
    froms = [ln.split()[1] for ln in text.splitlines() if ln.startswith("FROM ")]
    assert froms == [ext.DVWS_NODE22_IMAGE] * 2 and ext.DVWS_NODE22_IMAGE in ext.PINNED_IMAGES
    copies = [ln.split()[-2] for ln in text.splitlines() if ln.startswith("COPY ")]
    assert copies == [".cache/app", "/home/node/app"]
    assert "USER node" in text
    doc = yaml.safe_load((lab_dir / "compose.yaml").read_text("utf-8"))
    web = doc["services"]["web"]
    assert web["build"]["network"] == "none"                  # the build fetches nothing
    assert web["ports"] == ["127.0.0.1:${DVWS_PORT:-3102}:8080"]
    assert web["dns"] == ["127.0.0.1"]                        # no outside names resolve
    assert doc["networks"]["dvws-db"]["internal"] is True
    assert doc["services"]["mongo"]["image"] == ext.SECDEVLABS_MONGO_IMAGE
    assert doc["services"]["mysql"]["image"] == ext.MYSQL_IMAGE
    for db in ("mongo", "mysql"):
        assert doc["services"][db]["networks"] == ["dvws-db"]
        assert "ports" not in doc["services"][db]
        assert web["depends_on"][db]["condition"] == "service_healthy"


def _dvws_git_repo(path: Path, files: dict) -> str:
    import os
    import subprocess
    path.mkdir(parents=True)
    for name, data in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_bytes(data)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(path), *args], check=True, env=env,
                       capture_output=True)
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()


def test_dvws_is_fetched_at_the_pinned_tree_with_both_locked_package_sets(tmp_path, monkeypatch):
    """The checkout must hash to the pinned tree (else nothing is installed); it is copied
    without .git; the frontend's locked build set and the backend's production set are
    installed (each `npm ci`, integrity-checked, no scripts)."""
    from fuzzlab.lab_fixtures import external as ext
    src = tmp_path / "upstream"
    commit = _dvws_git_repo(src, {"package.json": b"{}", "src/server.js": b"//",
                                  "frontend/package.json": b"{}"})
    installs = []
    monkeypatch.setattr(ext, "npm_install",
                        lambda d, timeout, production=False: installs.append((d, production)))
    root = tmp_path / "external"
    with pytest.raises(ext.ExternalLabError, match="hash to"):
        ext.fetch_dvws_node(root=root, repo=str(src), commit=commit, tree="0" * 64)
    assert installs == []
    dest = ext.fetch_dvws_node(root=root, repo=str(src), commit=commit,
                               tree=ext.tree_sha256(src))
    assert dest == root / "dvws-node" / ".cache" / "app"
    assert (dest / "src" / "server.js").is_file() and not (dest / ".git").exists()
    assert installs == [(dest / "frontend", False), (dest, True)]


# --- end dvws-node ----------------------------------------------------------------------


# --- held-out lab fixture: railsgoat ----------------------------------------------------

class _RailsGoatApp:
    """RailsGoat's login, as measured live: POST /sessions with a seeded account's email
    and password answers 302 to /dashboard/home and sets the session cookie; the dashboard
    answers 200 with it (its links name /users/<id>/...) and 302 to the login without."""

    def __init__(self, users=None, dashboard_ids=("6",), anon_status=302):
        self.users = users if users is not None else {"ken@metacorp.com": "pw"}
        self.dashboard_ids, self.anon_status, self.log = dashboard_ids, anon_status, []

    def session(self):
        from types import SimpleNamespace
        app = self

        class S:
            headers, trust_env, proxies = {}, True, {}

            def __init__(self):
                self.user = None

            def request(self, method, url, data=None, **kw):
                path = url.split("3103", 1)[1]
                app.log.append((method, path, kw.get("allow_redirects")))
                r = SimpleNamespace(status_code=200, headers={}, text="", close=lambda: None)
                if path == "/sessions" and method == "POST":
                    if app.users.get(data.get("email")) == data.get("password"):
                        self.user = data["email"]
                        r.status_code = 302
                        r.headers = {"Location": "http://127.0.0.1:3103/dashboard/home"}
                    else:
                        r.text = "doesn't exist!"
                elif path == "/dashboard/home":
                    if self.user:
                        r.text = "".join(f'<a href="/users/{i}/work_info">' for i in
                                         app.dashboard_ids)
                    else:
                        r.status_code = app.anon_status
                return r
        return S()


def _rg_client(app):
    from fuzzlab.lab_fixtures import external as ext
    return ext._LabClient("http://127.0.0.1:3103", session_factory=app.session)


def _rg_cred(password="pw"):
    from fuzzlab.lab_fixtures import external as ext
    return ext.ResolvedCredential("ken@metacorp.com", password, "keyring")


def test_railsgoat_is_registered_with_two_seeded_accounts_on_loopback_3103():
    from fuzzlab.lab_fixtures import external as ext
    meta = ext.LAB_META["railsgoat"]
    assert (meta.port_env, meta.default_port, meta.container_port) == ("RAILSGOAT_PORT", 3103,
                                                                       3000)
    assert [(a.identity, a.default_username) for a in meta.accounts()] == [
        ("railsgoat-user", "ken@metacorp.com"), ("railsgoat-peer", "mike@metacorp.com")]
    assert meta.may_generate_password is False           # upstream's seed, never ours
    assert ext._BOOTSTRAPS["railsgoat"] is ext.bootstrap_railsgoat
    assert ext._ACCOUNT_ATTRIBUTES["railsgoat"] is ext.railsgoat_account_attributes


def test_the_railsgoat_bootstrap_logs_in_and_verifies_by_differential():
    from fuzzlab.lab_fixtures import external as ext
    app = _RailsGoatApp()
    assert ext.bootstrap_railsgoat(_rg_client(app), _rg_cred(), deadline=5,
                                   sleep=lambda s: None) == ["login verified"]
    assert ("POST", "/sessions", False) in app.log            # no redirect followed
    assert app.log.count(("GET", "/dashboard/home", False)) == 2   # with and without
    assert ext.railsgoat_account_attributes(_rg_client(app), _rg_cred()) == {"user_id": "6"}


def test_the_railsgoat_bootstrap_refuses_a_failed_login_or_an_open_dashboard():
    from fuzzlab.lab_fixtures import external as ext
    with pytest.raises(ext.ExternalLabError, match="login of 'ken@metacorp.com' failed"):
        ext.bootstrap_railsgoat(_rg_client(_RailsGoatApp()), _rg_cred("wrong"), deadline=5,
                                sleep=lambda s: None)
    with pytest.raises(ext.ExternalLabError, match="200 anonymous"):
        ext.bootstrap_railsgoat(_rg_client(_RailsGoatApp(anon_status=200)), _rg_cred(),
                                deadline=5, sleep=lambda s: None)


@pytest.mark.parametrize("ids", [(), ("5", "6")])
def test_the_railsgoat_user_id_must_be_one_dashboard_link(ids):
    from fuzzlab.lab_fixtures import external as ext
    with pytest.raises(ext.ExternalLabError, match="no single"):
        ext.railsgoat_account_attributes(_rg_client(_RailsGoatApp(dashboard_ids=ids)),
                                         _rg_cred())


_LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    rake (13.3.1)

CHECKSUMS
  ffi (1.17.3-x86_64-darwin) sha256={a}
  ffi (1.17.3-x86_64-linux-gnu) sha256={b}
  pg (1.6.3-x86_64-linux) sha256={c}
  rake (13.3.1) sha256={d}

RUBY VERSION
  ruby 3.4.1
"""


def test_gemfile_lock_checksums_pins_this_platforms_gems_and_fails_closed():
    from fuzzlab.lab_fixtures import external as ext
    a, b, c, d = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    assert ext.gemfile_lock_checksums(_LOCK.format(a=a, b=b, c=c, d=d)) == {
        "ffi-1.17.3-x86_64-linux-gnu.gem": b, "pg-1.6.3-x86_64-linux.gem": c,
        "rake-13.3.1.gem": d}
    with pytest.raises(ext.ExternalLabError, match="no CHECKSUMS"):
        ext.gemfile_lock_checksums("GEM\n  specs:\n")
    with pytest.raises(ext.ExternalLabError, match="no sha256"):        # unpinned gem
        ext.gemfile_lock_checksums(_LOCK.format(a=a, b=b, c=c, d=d).replace(
            f"rake (13.3.1) sha256={d}", "rake (13.3.1)"))
    # a gem of another platform may go unpinned: it is never downloaded
    assert "ffi-1.17.3-x86_64-darwin.gem" not in ext.gemfile_lock_checksums(
        _LOCK.format(a=a, b=b, c=c, d=d).replace(f" sha256={a}", ""))


def test_the_pinned_lock_has_checksums_for_every_gem_the_image_installs():
    """The pin holds for the pinned checkout's own lock when it is cached (offline)."""
    from fuzzlab.lab_fixtures import external as ext
    lock = ext.railsgoat_checkout() / "Gemfile.lock"
    if not lock.is_file():
        pytest.skip("RailsGoat checkout not cached (labctl.sh up railsgoat fetches it)")
    pins = ext.gemfile_lock_checksums(lock.read_text("utf-8"))
    assert "rails-8.0.4.gem" in pins and "sqlite3-2.9.0-x86_64-linux-gnu.gem" in pins


def test_fetch_rubygems_verifies_each_gem_rehashes_the_cache_and_prunes(tmp_path):
    import hashlib

    from fuzzlab.lab_fixtures import external as ext
    good = b"gem bytes"
    pins = {"x-1.0.gem": hashlib.sha256(good).hexdigest()}
    got = []

    def get(url, timeout):
        got.append(url)
        return good
    (tmp_path / "stale-0.1.gem").write_bytes(b"old")
    ext.fetch_rubygems(pins, tmp_path, get=get)
    assert got == ["https://rubygems.org/gems/x-1.0.gem"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x-1.0.gem"]
    ext.fetch_rubygems(pins, tmp_path, get=get)             # a good cache is kept
    assert len(got) == 1
    (tmp_path / "x-1.0.gem").write_bytes(b"tampered")       # a bad one is replaced
    ext.fetch_rubygems(pins, tmp_path, get=get)
    assert len(got) == 2 and (tmp_path / "x-1.0.gem").read_bytes() == good
    with pytest.raises(ext.ExternalLabError, match="differs from the pin"):
        ext.fetch_rubygems({"y-1.0.gem": "0" * 64}, tmp_path / "bad", get=get)
    assert list((tmp_path / "bad").iterdir()) == []         # nothing left behind


def test_railsgoat_is_fetched_at_the_pinned_tree_with_its_lock_verified_gems(tmp_path):
    import hashlib
    import subprocess

    from fuzzlab.lab_fixtures import external as ext
    gem = b"rake gem"
    lock = _LOCK.format(a="a" * 64, b="b" * 64, c="c" * 64,
                        d=hashlib.sha256(gem).hexdigest())
    src = tmp_path / "upstream"
    src.mkdir()
    (src / "Gemfile.lock").write_text(lock)
    (src / "config.ru").write_text("run Rails.application\n")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin"}
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(src), *args], check=True, env=env,
                       capture_output=True)
    commit = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()
    blobs = {"ffi-1.17.3-x86_64-linux-gnu.gem": b"ffi", "pg-1.6.3-x86_64-linux.gem": b"pg",
             "rake-13.3.1.gem": gem, "bundler-9.gem": b"bundler"}

    def get(url, timeout):
        return blobs[url.rsplit("/", 1)[1]]
    root = tmp_path / "external"
    bundler = ("bundler-9.gem", hashlib.sha256(b"bundler").hexdigest())
    with pytest.raises(ext.ExternalLabError, match="hash to"):
        ext.fetch_railsgoat(root=root, repo=str(src), commit=commit, tree="0" * 64,
                            bundler=bundler, get=get)
    with pytest.raises(ext.ExternalLabError, match="differs from the pin"):   # ffi, pg
        ext.fetch_railsgoat(root=root, repo=str(src), commit=commit,
                            tree=ext.tree_sha256(src), bundler=bundler, get=get)
    lock = lock.replace("b" * 64, hashlib.sha256(b"ffi").hexdigest()).replace(
        "c" * 64, hashlib.sha256(b"pg").hexdigest())
    (src / "Gemfile.lock").write_text(lock)
    subprocess.run(["git", "-C", str(src), "commit", "-qam", "y"], check=True, env=env,
                   capture_output=True)
    commit = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()
    dest = ext.fetch_railsgoat(root=root, repo=str(src), commit=commit,
                               tree=ext.tree_sha256(src), bundler=bundler, get=get)
    assert (dest / "config.ru").is_file() and not (dest / ".git").exists()
    assert sorted(p.name for p in (dest / "vendor" / "cache").iterdir()) == [
        "ffi-1.17.3-x86_64-linux-gnu.gem", "pg-1.6.3-x86_64-linux.gem", "rake-13.3.1.gem"]
    assert (root / "railsgoat" / ".cache" / "bundler" / "bundler-9.gem").read_bytes() == \
        b"bundler"


def test_the_railsgoat_build_uses_the_pinned_base_and_installs_offline():
    import yaml

    from fuzzlab.lab_fixtures import external as ext
    lab = REPO / "lab" / "external" / "railsgoat"
    text = (lab / "Dockerfile").read_text("utf-8")
    assert [ln.split()[1] for ln in text.splitlines() if ln.startswith("FROM ")] == [
        ext.RAILSGOAT_RUBY_IMAGE]
    assert ext.RAILSGOAT_RUBY_IMAGE in ext.PINNED_IMAGES
    assert ext.RAILSGOAT_BUNDLER_GEM[0] in text
    assert "bundle install --local" in text and "gem install --local" in text
    doc = yaml.safe_load((lab / "compose.yaml").read_text("utf-8"))
    web = doc["services"]["web"]
    assert web["build"]["network"] == "none"                 # the build fetches nothing
    assert web["read_only"] is True and web["cap_drop"] == ["ALL"]
    assert "cap_add" not in web and web["pids_limit"] and web["mem_limit"]
    assert web["ports"] == ["127.0.0.1:${RAILSGOAT_PORT:-3103}:3000"]


def _rg_published_session(page: str, status: int = 200):
    from types import SimpleNamespace

    class S:
        headers, trust_env, proxies = {}, True, {}

        def request(self, method, url, **kw):
            text = page if url.endswith("/tutorials/credentials") else ""
            return SimpleNamespace(status_code=status, headers={}, text=text,
                                   close=lambda: None)
    return S


class _MemKeyring:
    def __init__(self, existing=None):
        self.data = dict(existing or {})

    def get(self, host, identity):
        return self.data.get((host, identity))

    def set(self, host, identity, username, password):
        from types import SimpleNamespace
        self.data[(host, identity)] = SimpleNamespace(username=username, password=password)


_RG_TABLE = ("<table><tbody><tr>\n  <td style=\"x\">mike@metacorp.com</td>\n"
             "  <td>m-pass</td>\n  <td>4-abc</td>\n</tr><tr>\n"
             "  <td style=\"x\">ken@metacorp.com</td>\n  <td>k-pass</td>\n"
             "  <td>5-def</td>\n</tr></tbody></table>")


def test_railsgoat_seeded_passwords_are_read_from_its_own_page_into_the_keyring():
    """FR-LAB-425: an unattended run (fresh keyring, no TTY) stores the passwords the
    app publishes for each account it has none for, and only those."""
    from fuzzlab.lab_fixtures import external as ext
    kr = _MemKeyring()
    stored = ext.seed_published_credentials(
        "railsgoat", environ={}, keyring_store=kr,
        session_factory=_rg_published_session(_RG_TABLE), deadline=5)
    assert stored == ["railsgoat-user", "railsgoat-peer"]
    assert kr.get("127.0.0.1", "railsgoat-user").password == "k-pass"
    assert kr.get("127.0.0.1", "railsgoat-peer").username == "mike@metacorp.com"
    again = ext.seed_published_credentials(
        "railsgoat", environ={}, keyring_store=kr,
        session_factory=_rg_published_session(""), deadline=5)
    assert again == []                      # already stored: the page is not even read


@pytest.mark.parametrize("page,status", [("<p>nothing</p>", 200), (_RG_TABLE, 500)])
def test_railsgoat_seeding_refuses_a_page_without_the_account(page, status):
    from fuzzlab.lab_fixtures import external as ext
    kr = _MemKeyring()
    with pytest.raises(ext.ExternalLabError):
        ext.seed_published_credentials("railsgoat", environ={}, keyring_store=kr,
                                       session_factory=_rg_published_session(page, status),
                                       deadline=5)
    assert kr.data == {}


def test_seeding_refuses_a_lab_that_publishes_no_credentials():
    from fuzzlab.lab_fixtures import external as ext
    with pytest.raises(ext.ExternalLabError):
        ext.seed_published_credentials("nodegoat", keyring_store=_MemKeyring())


# --- end railsgoat ----------------------------------------------------------------------
