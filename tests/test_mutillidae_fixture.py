"""The Mutillidae II external lab fixture (CC-LAB-0340, CC-LAB-0341; FR-LAB-340,
FR-LAB-341): its pinned LDIF fetch, the directory load and the bootstrap, against fakes.
The live boot is `tests/test_mutillidae_live.py` (gated)."""

from __future__ import annotations

import hashlib
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from fuzzlab.lab_fixtures import external as ext

LDIF = b"dn: dc=mutillidae,dc=localhost\n"
PIN = {"sha256": hashlib.sha256(LDIF).hexdigest(), "size": len(LDIF)}


def test_the_compose_file_pins_upstreams_three_images_and_hides_db_and_directory():
    doc = yaml.safe_load((ext.EXTERNAL_DIR / "mutillidae" / "compose.yaml").read_text())
    svc = doc["services"]
    assert {svc[n]["image"] for n in svc} == {ext.MUTILLIDAE_WWW_IMAGE,
                                              ext.MUTILLIDAE_DATABASE_IMAGE,
                                              ext.MUTILLIDAE_LDAP_IMAGE}
    # upstream's code names its database and directory by these service names
    assert {"database", "directory"} <= set(svc)
    for name in ("database", "directory"):
        assert "ports" not in svc[name]
        assert all(doc["networks"][n].get("internal") is True for n in svc[name]["networks"])
    assert set(svc["www"]["networks"]) - {n for n in doc["networks"]
                                          if doc["networks"][n].get("internal")} \
        == {"mutillidae-front"}


def test_the_ldif_is_fetched_verified_and_a_bad_cache_replaced(tmp_path):
    dest = tmp_path / "m.ldif"
    calls = []

    def get(url, timeout):
        calls.append(url)
        return LDIF
    assert ext.fetch_mutillidae_ldif(dest=dest, get=get, **PIN).read_bytes() == LDIF
    assert calls == [ext.MUTILLIDAE_LDIF_URL]
    assert ext.MUTILLIDAE_DOCKER_COMMIT in ext.MUTILLIDAE_LDIF_URL
    ext.fetch_mutillidae_ldif(dest=dest, get=get, **PIN)          # cached: re-hashed, kept
    assert len(calls) == 1
    dest.write_bytes(b"tampered")
    ext.fetch_mutillidae_ldif(dest=dest, get=get, **PIN)
    assert len(calls) == 2 and dest.read_bytes() == LDIF


def test_a_mismatched_ldif_leaves_nothing_behind(tmp_path):
    dest = tmp_path / "m.ldif"
    with pytest.raises(ext.ExternalLabError, match="does not match the pin"):
        ext.fetch_mutillidae_ldif(dest=dest, get=lambda u, t: LDIF + b"x", **PIN)
    assert not dest.exists() and not list(tmp_path.iterdir())


class _Runner:
    """Records each command; ``ps`` lists ``containers``; ``exec`` answers the next
    exit code of ``codes``."""

    def __init__(self, containers=("c0ffee",), codes=(0,)):
        self.containers, self.codes, self.calls = list(containers), list(codes), []

    def __call__(self, argv, *, timeout, input=None, **kw):
        self.calls.append((argv, input))
        if argv[1] == "ps":
            return subprocess.CompletedProcess(argv, 0, "\n".join(self.containers), "")
        return subprocess.CompletedProcess(argv, self.codes.pop(0),
                                           "adding new entry \"x\"\n", "boom")


def _ldif(tmp_path):
    path = tmp_path / "m.ldif"
    path.write_bytes(LDIF)
    return path


def test_the_directory_load_targets_the_projects_directory_by_label(tmp_path, monkeypatch):
    monkeypatch.setattr(ext, "MUTILLIDAE_LDIF_SHA256", PIN["sha256"])
    run = _Runner(codes=(68,))                     # entries already there: kept
    note = ext.load_mutillidae_directory("docker", "fuzzlab-mutillidae", runner=run,
                                         ldif=_ldif(tmp_path))
    ps, (exec_argv, sent) = run.calls[0][0], run.calls[1]
    assert "label=com.docker.compose.project=fuzzlab-mutillidae" in ps
    assert "label=com.docker.compose.service=directory" in ps
    assert exec_argv[:4] == ["docker", "exec", "-i", "c0ffee"] and "ldapadd" in exec_argv
    assert "-c" in exec_argv and sent == LDIF.decode()             # on stdin, nothing mounted
    assert "directory loaded" in note


def test_the_directory_load_waits_for_slapd_then_fails_loudly(tmp_path, monkeypatch):
    monkeypatch.setattr(ext, "MUTILLIDAE_LDIF_SHA256", PIN["sha256"])
    clock = iter(range(0, 1000, 10))
    kw = dict(ldif=_ldif(tmp_path), deadline=25, clock=lambda: next(clock),
              sleep=lambda s: None)
    run = _Runner(codes=(255, 255, 0))
    ext.load_mutillidae_directory("docker", "p", runner=run, **kw)
    assert [c[0][1] for c in run.calls] == ["ps", "exec", "exec", "exec"]
    with pytest.raises(ext.ExternalLabError, match="ldapadd exited 255"):
        ext.load_mutillidae_directory("docker", "p", runner=_Runner(codes=(255,) * 9), **kw)
    with pytest.raises(ext.ExternalLabError, match="ldapadd exited 1"):
        ext.load_mutillidae_directory("docker", "p", runner=_Runner(codes=(1,)), **kw)


@pytest.mark.parametrize("containers", [(), ("a", "b")])
def test_the_directory_load_wants_exactly_one_container(tmp_path, monkeypatch, containers):
    monkeypatch.setattr(ext, "MUTILLIDAE_LDIF_SHA256", PIN["sha256"])
    with pytest.raises(ext.ExternalLabError, match="want one running directory"):
        ext.load_mutillidae_directory("docker", "p", runner=_Runner(containers),
                                      ldif=_ldif(tmp_path))


def test_the_directory_load_refuses_an_ldif_off_its_pin(tmp_path):
    with pytest.raises(ext.ExternalLabError, match="does not match its pin"):
        ext.load_mutillidae_directory("docker", "p", runner=_Runner(), ldif=_ldif(tmp_path))


# --- bootstrap ----------------------------------------------------------------------------

class _App:
    """Mutillidae's answers, as measured (CC-LAB-0341): an offline database redirects
    the home page; a login keeps only a session that existed before it; a registered
    account logs in with a 302 to AU1; an authenticated page redirects without one."""

    def __init__(self, db=False, registered=False, rooms=True, db_starts=0):
        self.db, self.users, self.rooms, self.db_starts = db, {}, rooms, db_starts
        if registered:
            self.users["fuzzlab_user"] = "pw"
        self.log = []

    def session(self):
        app = self

        class S:
            headers, trust_env, proxies, cookies = {}, True, {}, {}

            def __init__(self):
                self.sid = None
                self.user = None

            def request(self, method, url, data=None, **kw):
                path = url.split("3093", 1)[1]
                app.log.append((method, path))
                had = self.sid
                self.sid = self.sid or "s1"
                r = SimpleNamespace(status_code=200, headers={}, text="",
                                    close=lambda: None)
                if path == "/":
                    if not app.db:
                        r.status_code, r.headers = 302, {"Location": "database-offline.php"}
                elif path == "/set-up-database.php":
                    if app.db_starts:              # the database is still starting
                        app.db_starts -= 1
                        r.text = "Failed to connect to MySQL server"
                    else:
                        app.db = True
                        r.text = "Connected to MySQL server at database as root"
                elif path.endswith("page=login.php") and method == "POST":
                    if had and app.users.get(data["username"]) == data["password"]:
                        self.user = data["username"]
                        r.status_code = 302
                        r.headers = {"Location": "index.php?popUpNotificationCode=AU1"}
                elif path.endswith("page=register.php"):
                    app.users[data["username"]] = data["password"]
                    r.text = f"Account created for {data['username']}. 1 rows inserted."
                elif path.endswith("page=user-info.php"):
                    if not self.user:
                        r.status_code = 302
                elif path.endswith("page=conference-room-lookup.php"):
                    r.text = "<td>1F104</td>" if app.rooms else "<td>2F204</td>"
                return r
        return S()


def _boot(app, **kw):
    client = ext._LabClient("http://127.0.0.1:3093", session_factory=app.session)
    cred = ext.ResolvedCredential("fuzzlab_user", "pw", "generated")
    return ext.bootstrap_mutillidae(client, cred, deadline=5, sleep=lambda s: None, **kw)


def test_the_database_build_waits_for_the_database_then_fails_loudly():
    """Measured live (the gated test's first run): on a fresh boot set-up-database.php
    answers 200 without connecting while MariaDB starts."""
    app = _App(db_starts=2)
    assert _boot(app)[0] == "database built"
    assert app.log.count(("GET", "/set-up-database.php")) == 3
    clock = iter(range(0, 1000, 10))
    with pytest.raises(ext.ExternalLabError, match="did not connect to the database"):
        _boot(_App(db_starts=99), clock=lambda: next(clock))


def test_a_fresh_lab_is_built_registered_logged_in_and_checked():
    app = _App()
    notes = _boot(app)
    assert notes == ["database built", "account registered", "login verified",
                     "directory verified"]
    # the form page is read before each login (a login with no session is not kept)
    posts = [i for i, e in enumerate(app.log) if e == ("POST", "/index.php?page=login.php")]
    assert all(app.log[i - 1] == ("GET", "/index.php?page=login.php") for i in posts)


def test_a_ready_lab_only_logs_in():
    assert _boot(_App(db=True, registered=True)) == ["login verified", "directory verified"]


def test_an_empty_directory_fails_the_bootstrap():
    with pytest.raises(ext.ExternalLabError, match="no room 1F104"):
        _boot(_App(db=True, registered=True, rooms=False))


def test_the_lab_meta_names_a_query_routed_ready_page_and_our_own_account():
    meta = ext.LAB_META["mutillidae"]
    assert meta.ready_path == "/index.php?page=login.php" and meta.may_generate_password
    assert meta.identity == "mutillidae-user" and meta.service == "www"
