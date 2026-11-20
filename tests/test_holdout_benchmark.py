"""The held-out benchmark's own tests (lab/HOLDOUT.md, FR-LAB-420..423, FR-CORE-680..).

This is the ONLY test file that may name a held-out lab (lab/HOLDOUT.md rule 4). It
holds: the guard that enforces that rule, the table parser's checks, the benchmark
script's offline checks (``scripts/holdout_score.py`` against fakes: nothing here
sends traffic), and each held-out lab fixture's unit tests (its bootstrap against a fake
client). No test here runs a held-out lab or reads its answer key for anything but
structure.
"""

from __future__ import annotations

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


# --- end railsgoat ----------------------------------------------------------------------
