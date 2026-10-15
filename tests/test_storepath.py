"""FR-CORE-400: the one store resolution, shared by every CLI and the web UI's config."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fuzzlab.core import storepath
from fuzzlab.core.config import DEFAULTS, Config, load_config
from fuzzlab.core.storepath import (DEFAULT_STORE, StorePathError, check_readable,
                                    check_writable, from_environ, resolve)


# --- resolution order ---------------------------------------------------------------

def test_order_flag_then_fuzzlab_store_then_store_path_then_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env = {"FUZZLAB_STORE": "a.db", "FUZZLAB_STORE_PATH": "b.db"}
    assert resolve("x.db", environ=env) == storepath.ResolvedStore(tmp_path / "x.db",
                                                                  "--store")
    assert resolve(None, environ=env).source == "FUZZLAB_STORE"
    assert resolve(None, environ=env).path == tmp_path / "a.db"
    only_path = {"FUZZLAB_STORE_PATH": "b.db"}
    assert resolve(None, environ=only_path).source == "FUZZLAB_STORE_PATH"
    assert resolve(None, environ={}).path == tmp_path / DEFAULT_STORE
    assert resolve(None, environ={}).is_default


def test_resolve_store_reads_the_process_environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert storepath.resolve_store(None) == tmp_path / DEFAULT_STORE
    monkeypatch.setenv("FUZZLAB_STORE", str(tmp_path / "e.db"))
    assert storepath.resolve_store(None) == tmp_path / "e.db"
    assert storepath.resolve_store("f.db") == tmp_path / "f.db"     # --store still wins


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_an_empty_environment_value_is_unset(value, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env = {"FUZZLAB_STORE": value, "FUZZLAB_STORE_PATH": value}
    assert from_environ(env) is None
    assert resolve(None, environ=env).is_default
    # an empty FUZZLAB_STORE falls through to a real FUZZLAB_STORE_PATH
    assert resolve(None, environ={"FUZZLAB_STORE": value,
                                  "FUZZLAB_STORE_PATH": "p.db"}).source == \
        "FUZZLAB_STORE_PATH"


@pytest.mark.parametrize("value", ["", " "])
def test_an_explicit_empty_store_flag_is_a_usage_error_not_absent(value):
    with pytest.raises(StorePathError, match="empty path"):
        resolve(value, environ={})


def test_tilde_is_expanded_on_every_input(monkeypatch):
    home = os.path.expanduser("~")
    assert resolve("~/a.db", environ={}).path == Path(home) / "a.db"
    assert resolve(None, environ={"FUZZLAB_STORE": "~/b.db"}).path == Path(home) / "b.db"
    assert from_environ({"FUZZLAB_STORE_PATH": "~/c.db"})[0] == os.path.join(home, "c.db")


def test_from_environ_never_raises_on_odd_values():
    for env in ({}, {"FUZZLAB_STORE": "\x00"}, {"FUZZLAB_STORE_PATH": "~nouser/x"},
                {"FUZZLAB_STORE": "a" * 5000}):
        from_environ(env)


def test_resolve_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for value in (None, "sub/dir/x.db", "y.db"):
        resolve(value, environ={})
    assert list(tmp_path.iterdir()) == []


def test_describe_names_the_path_and_its_source(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert storepath.describe(resolve(None, environ={})) == \
        f"store: {tmp_path / DEFAULT_STORE} (default)"
    assert storepath.describe(resolve(None, environ={"FUZZLAB_STORE": "q.db"})) == \
        f"store: {tmp_path / 'q.db'} (FUZZLAB_STORE)"


# --- boundary checks (typed errors, PA-0021) -----------------------------------------

def test_check_readable_refuses_missing_directory_and_non_regular(tmp_path):
    with pytest.raises(StorePathError, match="no such store"):
        check_readable(resolve(str(tmp_path / "missing.db"), environ={}))
    with pytest.raises(StorePathError, match="not a store file"):
        check_readable(resolve(str(tmp_path), environ={}))
    fifo = tmp_path / "pipe.db"
    os.mkfifo(fifo)
    with pytest.raises(StorePathError, match="not a store file"):
        check_readable(resolve(str(fifo), environ={}))
    real = tmp_path / "ok.db"
    real.write_bytes(b"")
    check_readable(resolve(str(real), environ={}))


def test_check_readable_on_a_missing_default_says_how_to_get_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(StorePathError, match=r"default store\); run a command"):
        check_readable(resolve(None, environ={}))


def test_check_writable_refuses_a_missing_directory_and_a_directory(tmp_path):
    with pytest.raises(StorePathError, match="does not exist"):
        check_writable(resolve(str(tmp_path / "nope" / "x.db"), environ={}))
    with pytest.raises(StorePathError, match="not a store file"):
        check_writable(resolve(str(tmp_path), environ={}))
    check_writable(resolve(str(tmp_path / "new.db"), environ={}))      # parent exists
    assert not (tmp_path / "new.db").exists()                         # and nothing created


def test_store_path_error_is_a_value_error():
    assert issubclass(StorePathError, ValueError)


# --- the web UI's config uses the same resolution ------------------------------------

def test_config_default_is_the_one_literal_and_the_hash_is_unchanged():
    assert DEFAULTS["store_path"] is DEFAULT_STORE
    cfg = load_config(environ={})
    assert cfg["store_path"] == DEFAULT_STORE
    # the pre-change computation over the source of truth (no frozen literal; PA-0001)
    assert cfg.hash() == Config(values=dict(DEFAULTS)).hash()


@pytest.mark.parametrize("env, source", [
    ({"FUZZLAB_STORE": "s.db"}, "FUZZLAB_STORE"),
    ({"FUZZLAB_STORE_PATH": "p.db"}, "FUZZLAB_STORE_PATH"),
    ({"FUZZLAB_STORE": "s.db", "FUZZLAB_STORE_PATH": "p.db"}, "FUZZLAB_STORE"),
    ({"FUZZLAB_STORE": "~/t.db"}, "FUZZLAB_STORE"),
    ({"FUZZLAB_STORE": "", "FUZZLAB_STORE_PATH": ""}, "default"),
    ({"FUZZLAB_STORE_PATH": "  "}, "default"),
])
def test_the_ui_config_and_the_cli_pick_the_same_store(env, source, tmp_path,
                                                       monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli = resolve(None, environ=env)
    ui = Path(os.path.abspath(load_config(environ=env)["store_path"]))
    assert cli.source == source
    assert ui == cli.path


def test_an_override_still_wins_over_the_environment():
    cfg = load_config(overrides={"store_path": "/o.db"},
                      environ={"FUZZLAB_STORE": "/e.db"})
    assert cfg["store_path"] == "/o.db"


def test_load_config_never_raises_because_of_the_store():
    for env in ({"FUZZLAB_STORE": ""}, {"FUZZLAB_STORE": "/a", "FUZZLAB_STORE_PATH": "/b"},
                {"FUZZLAB_STORE_PATH": "~/x.db"}):
        load_config(environ=env)


# --- the suite's own isolation (tests/_store_guard.py) -------------------------------

@pytest.fixture(scope="module")
def env_seen_by_a_module_fixture():
    """What a module-scoped fixture (set up before any function-scoped one) sees."""
    return {n: os.environ.get(n) for n in storepath.ENV_NAMES}


def test_tests_run_with_the_store_variables_cleared(env_seen_by_a_module_fixture):
    """Cleared per test, and already at session start (review A9: module- and
    session-scoped fixtures and their child processes never see a host value)."""
    assert not any(os.environ.get(n) for n in storepath.ENV_NAMES)
    assert not any(env_seen_by_a_module_fixture.values())


def test_the_store_guard_sees_a_new_store_and_a_write_to_an_existing_one(tmp_path):
    from tests._store_guard import store_files
    assert store_files(tmp_path) == {}
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / DEFAULT_STORE).write_bytes(b"x")
    first = store_files(tmp_path)
    assert list(first) == [str(deep / DEFAULT_STORE)]
    (deep / DEFAULT_STORE).write_bytes(b"xy")
    (deep / (DEFAULT_STORE + "-wal")).write_bytes(b"")
    second = store_files(tmp_path)
    assert second[str(deep / DEFAULT_STORE)] != first[str(deep / DEFAULT_STORE)]
    assert str(deep / (DEFAULT_STORE + "-wal")) in second
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / DEFAULT_STORE).write_bytes(b"")
    assert str(tmp_path / ".git" / DEFAULT_STORE) not in store_files(tmp_path)


def test_the_store_guard_never_walks_pytests_temp_base_nor_an_outside_cwd(tmp_path):
    """BUG-0402: pytest's own temp base (inside the tree) is excluded, and a cwd outside
    the repository is checked for its own store files only, never walked."""
    from tests._store_guard import store_files
    repo, base, outside = tmp_path / "repo", tmp_path / "repo" / "tmpbase", tmp_path / "home"
    (base / "test_x0").mkdir(parents=True)
    (outside / "otherproj").mkdir(parents=True)
    (base / "test_x0" / DEFAULT_STORE).write_bytes(b"")          # a test's own tmp store
    (outside / "otherproj" / DEFAULT_STORE).write_bytes(b"")     # someone else's store
    (outside / DEFAULT_STORE).write_bytes(b"")                   # the cwd's own store
    found = store_files(repo, exclude=[str(base)], cwd=str(outside))
    assert list(found) == [str(outside / DEFAULT_STORE)]


def test_the_guard_watches_an_outside_cwd_and_excludes_pytests_basetemp(tmp_path,
                                                                        monkeypatch):
    """PA-0402(3): the fixture's own wiring (`guard_kwargs`), from a cwd outside the
    repository and from inside it."""
    from tests._store_guard import ROOT, guard_kwargs
    monkeypatch.chdir(tmp_path)
    kwargs = guard_kwargs(tmp_path / "base")
    assert kwargs == {"exclude": [str(tmp_path / "base")], "cwd": tmp_path.resolve()}
    monkeypatch.chdir(ROOT / "docs")
    assert guard_kwargs(tmp_path / "base")["cwd"] is None


def test_pytest_configure_clears_the_store_variables(monkeypatch):
    """The session-wide clear itself (not only the per-test fixture), with a host value."""
    from tests._store_guard import pytest_configure
    for name in storepath.ENV_NAMES:
        monkeypatch.setenv(name, "/host/store.db")
    pytest_configure(None)
    assert not any(n in os.environ for n in storepath.ENV_NAMES)


def test_a_malformed_trained_on_is_unknown_never_a_default():
    """PA-0108(2): absent = run (run-mode and legacy rows); an unknown value is None."""
    from fuzzlab.core.modelinfo import trained_on
    from fuzzlab.report.report import _training
    assert trained_on({}) == "run"
    assert trained_on({"trained_on": "earlier"}) == "earlier"
    assert trained_on({"trained_on": "saved"}) == "saved"
    for bad in (5, "bogus", None, ["run"]):
        assert trained_on({"trained_on": bad}) is None
        assert _training({"trained_on": bad})["trained_on"] == "unknown"


def test_the_default_stays_the_shared_project_store():
    """The literal the UI has always used (pinned: a move is the owner's decision, §4.8)."""
    assert DEFAULT_STORE == "fuzzlab.db"
    assert storepath.DEFAULT_RULE.endswith(f"./{DEFAULT_STORE}")


def test_check_writable_refuses_a_fifo(tmp_path):
    fifo = tmp_path / "pipe.db"
    os.mkfifo(fifo)
    with pytest.raises(StorePathError, match="not a store file"):
        check_writable(resolve(str(fifo), environ={}))


def test_gitignore_ignores_a_default_store_at_any_depth():
    import shutil
    import subprocess
    root = Path(__file__).resolve().parents[1]
    if shutil.which("git") is None or not (root / ".git").exists():
        pytest.skip("needs a git checkout")
    paths = [DEFAULT_STORE + s for s in ("", "-journal", "-wal", "-shm")]
    paths += [f"lab/{DEFAULT_STORE}", f"docs/sub/{DEFAULT_STORE}-journal"]
    r = subprocess.run(["git", "check-ignore", "--no-index", *paths], cwd=root,
                       capture_output=True, text=True)
    assert sorted(r.stdout.split()) == sorted(paths)
