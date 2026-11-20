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


# --- end railsgoat ----------------------------------------------------------------------
