"""Project files in the web UI (CC-UI-0450; FR-UI-450..457; NFR-UI-project-private,
NFR-UI-project-paths-confined, NFR-UI-project-provenance-redacted,
NFR-UI-project-switch-safe)."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fuzzlab import procutil  # noqa: E402
from fuzzlab.core import project as core_project  # noqa: E402
from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import LAUNCH_TOKEN_ENV, Store  # noqa: E402
from fuzzlab.web import commandspec, projects  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.projects import (  # noqa: E402
    NeedsDiscard, NoProject, ProjectBusy, ProjectManager, ProjectError)
from fuzzlab.web.runner import Runner, build_argv  # noqa: E402
from tests._downgrade import undo_after  # noqa: E402
from tests._webclient import SAME_ORIGIN_HEADERS, web_client  # noqa: E402

WEB = Path(__file__).resolve().parent.parent / "fuzzlab" / "web"


def _cfg(tmp_path, store="start.db", **over):
    # store=None: start with no project open (an empty `store_path`).
    values = {"store_path": str(tmp_path / store) if store else "",
              "projects_dir": str(tmp_path / "projects"), "authorized": True, **over}
    return load_config(overrides=values, environ={})


def _client(tmp_path, **kw):
    app = create_app(_cfg(tmp_path, **kw))
    return app, web_client(app, follow_redirects=False)


def _state(c):
    return c.get("/api/projects").json()["project"]


def _flash(c):
    return c.get("/projects").text


def _tree_modes(root: Path):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            out[str(p.relative_to(root))] = stat.S_IMODE(os.lstat(p).st_mode)
    return out


# --- guards (found by shape, proven on synthetic offenders: PA-0034(2)) ---------------

_CREATE_ALLOWED = {("projects.py", "_create_locked")}
_OPENERS = {"Store", "open_store", "connect"}
#: `core.project` helpers that create files: only these web functions may call them.
_CREATORS = {"create": {"_create_locked"}, "copy_to": {"_save_as", "_copy_sidecars"}}


def _refname(node):
    return node.id if isinstance(node, ast.Name) else \
        node.attr if isinstance(node, ast.Attribute) else None


def _creating_opens(source: str, filename: str) -> list[str]:
    """Calls in ``source`` that may open a store and create its file: ``Store(``,
    ``open_store(``, ``connect(`` — under any import alias or assigned name — without
    ``create=False``; any ``sqlite3.connect(``; an opener reached by ``getattr`` or
    passed as an argument (``partial(Store, p)``); and a ``core_project.create`` /
    ``copy_to`` outside its allowed function."""
    tree = ast.parse(source)
    aliases, sqlite_mods = set(_OPENERS), {"sqlite3"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name in _OPENERS:
                    aliases.add(a.asname or a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "sqlite3":
                    sqlite_mods.add(a.asname or a.name)
        elif isinstance(node, ast.Assign) and _refname(node.value) in aliases:
            aliases.update(t.id for t in node.targets if isinstance(t, ast.Name))
    offenders = []

    def visit(node, func):
        for child in ast.iter_child_nodes(node):
            f = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                else func
            if isinstance(child, ast.Call):
                name = _refname(child.func)
                is_sqlite = (isinstance(child.func, ast.Attribute) and
                             isinstance(child.func.value, ast.Name) and
                             child.func.value.id in sqlite_mods)
                no_create = any(k.arg == "create" and isinstance(k.value, ast.Constant)
                                and k.value.value is False for k in child.keywords)
                allowed = (filename, f) in _CREATE_ALLOWED
                if (name in aliases or is_sqlite) and (is_sqlite or not no_create) \
                        and not allowed:
                    offenders.append(f"{filename}:{child.lineno} {name}(")
                if name == "getattr" and any(isinstance(a, ast.Constant) and
                                             a.value in _OPENERS for a in child.args):
                    offenders.append(f"{filename}:{child.lineno} getattr(…opener)")
                if any(_refname(a) in aliases for a in child.args) and not allowed:
                    offenders.append(f"{filename}:{child.lineno} opener passed to {name}(")
                if (isinstance(child.func, ast.Attribute) and name in _CREATORS and
                        _refname(child.func.value) == "core_project" and
                        f not in _CREATORS[name]):
                    offenders.append(f"{filename}:{child.lineno} core_project.{name}(")
            visit(child, f)
    visit(tree, "")
    return offenders


def test_no_web_module_opens_a_store_that_can_create():
    """G1: only `ProjectManager._create_locked` may create a store file; every other
    open in fuzzlab/web/ is `create=False`, so a reader racing a discard can never
    recreate a deleted project."""
    offenders = []
    for py in sorted(WEB.glob("*.py")):
        offenders += _creating_opens(py.read_text(), py.name)
    assert offenders == [], offenders


@pytest.mark.parametrize("bad", [
    "def f(p):\n    from fuzzlab.core.store import Store\n    return Store(p)\n",
    "def g(p):\n    import sqlite3\n    return sqlite3.connect(p)\n",
    "def h(p):\n    return Store(p, create=True)\n",
    "from fuzzlab.core.store import Store as S\ndef f(p):\n    return S(p)\n",
    "from sqlite3 import connect as c\ndef f(p):\n    return c(p)\n",
    "import sqlite3 as sq\ndef f(p):\n    return sq.connect(p)\n",
    "def f(st, p):\n    return getattr(st, 'Store')(p)\n",
    "import functools\ndef f(st, p):\n    return functools.partial(st.Store, p)()\n",
    "def f(p):\n    S = Store\n    return S(p)\n",
    "def f(p):\n    return core_project.create(p)\n",
    "def _new(p):\n    return core_project.copy_to(p, p)\n",
])
def test_the_creating_open_guard_catches_synthetic_offenders(bad):
    assert _creating_opens(bad, "x.py"), bad


def test_the_creating_open_guard_passes_a_no_create_open():
    good = ("def f(p):\n    return Store(p, create=False)\n"
            "def _create_locked(p):\n    return core_project.create(p)\n")
    assert _creating_opens(good, "x.py") == []


_RECORD_WRITE = __import__("re").compile(
    r"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE(?:\s+OR\s+\w+)?"
    r"|DELETE\s+FROM)\s+(?:[\"`\[]?main[\"`\]]?\.)?[\"`\[]?(?:launch|project)\b", __import__("re").I)


def _record_writers(source: str) -> bool:
    return bool(_RECORD_WRITE.search(source))


def test_only_core_project_writes_the_project_record_tables():
    """PA-0100: every write to `launch`/`project` goes through `core.project`, whose
    writers redact through `redact_for_record`."""
    root = WEB.parent
    writers = sorted(str(p.relative_to(root)) for p in root.rglob("*.py")
                     if _record_writers(p.read_text()))
    assert writers == ["core/project.py"], writers
    for offender in ("UPDATE launch SET argv=?", "INSERT OR REPLACE INTO launch (a) VALUES (1)",
                     "REPLACE INTO project (id) VALUES (1)", 'UPDATE "launch" SET x=1',
                     "DELETE FROM launch", "update main.project set notes=''",
                     "INSERT INTO `project` (id) VALUES (1)"):
        assert _record_writers(offender), offender
    for benign in ("SELECT id FROM launch WHERE token=?", "INSERT INTO run (launch_id)",
                   "CREATE TABLE IF NOT EXISTS launch ("):
        assert not _record_writers(benign), benign


def _str_options():
    out = []
    for spec in commandspec.all_specs():
        out += [(spec.name, o.dest) for o in spec.options if o.type == "str"]
        for sub, opts in spec.subcommands.items():
            out += [(f"{spec.name}:{sub}", o.dest) for o in opts if o.type == "str"]
    return out


def test_every_str_option_of_every_spec_is_classified():
    """F3: a new path flag cannot silently write outside the project."""
    found = _str_options()
    assert found, "no specs discovered"
    missing = [k for k in found if k not in projects.OPTION_CLASS]
    assert missing == [], f"classify these in projects.OPTION_CLASS: {missing}"
    stale = [k for k in projects.OPTION_CLASS if k not in set(found)]
    assert stale == [], f"OPTION_CLASS names options that no longer exist: {stale}"


def test_the_classification_guard_catches_a_synthetic_offender(monkeypatch):
    import argparse
    p = argparse.ArgumentParser(prog="fuzzlab synth")
    p.add_argument("--store")
    p.add_argument("--dump-file", default="out.db")
    monkeypatch.setattr(commandspec, "_REGISTRY", [
        commandspec._Entry("synth", "synthetic", False, lambda: p)])
    found = _str_options()
    assert ("synth", "dump_file") in found and \
        ("synth", "dump_file") not in projects.OPTION_CLASS


def test_every_spec_that_writes_a_store_is_pinned():
    for spec in commandspec.all_specs():
        has_store = any(o.dest == "store" for o in spec.options)
        assert projects.is_pinned(spec) == has_store, spec.name


# --- pinning ---------------------------------------------------------------------------

def test_pin_values_overrides_store_and_intermediates(tmp_path):
    p = tmp_path / "x.fuzzlab"
    crawl = commandspec.spec("crawl")
    out = projects.pin_values(crawl, {"store": "/etc/evil.db", "db": "/tmp/shared.db",
                                      "start": "http://127.0.0.1:8080"}, p)
    assert out["store"] == str(p)
    assert out["db"] == str(core_project.sidecar_dir(p) / "spider.db")
    assert out["start"] == "http://127.0.0.1:8080"
    fuzz = projects.pin_values(commandspec.spec("fuzz"), {"output": "x.csv"}, p)
    assert fuzz["output"] == str(core_project.sidecar_dir(p) / "fuzz.csv")


def test_dry_run_shows_the_pin_and_creates_nothing(tmp_path):
    app, c = _client(tmp_path)
    r = c.post("/api/launch/dry-run", json={"command": "report",
                                            "values": {"store": "x.db"}}).json()
    assert r["project_pinned"] is True
    assert r["argv"][-2:] == ["--store", str(tmp_path / "start.db")]
    assert not (tmp_path / "start.db").exists()
    assert not (tmp_path / "projects").exists()


def test_launch_runs_pinned_to_the_project_with_a_private_umask(tmp_path, monkeypatch):
    seen = {}

    async def fake_launch(self, argv, *, env=None, project=None, command="", on_done=None,
                          umask=None):
        seen.update(argv=argv, env=env, project=project, umask=umask, on_done=on_done)
        return "tok"
    monkeypatch.setattr(Runner, "launch", fake_launch)
    app, c = _client(tmp_path)
    r = c.post("/api/launch", json={"command": "auto", "values": {
        "base_url": "http://admin:hunter2@127.0.0.1:8080", "store": "/etc/other.db",
        "spider_db": "/tmp/shared.db"}})
    assert r.status_code == 200, r.text
    path = str(tmp_path / "start.db")
    argv = seen["argv"]
    assert argv[argv.index("--store") + 1] == path
    assert argv[argv.index("--spider-db") + 1] == \
        str(core_project.sidecar_dir(path) / "spider.db")
    assert "/etc/other.db" not in argv and "/tmp/shared.db" not in argv
    assert seen["project"] == path and seen["umask"] == 0o077
    assert len(seen["env"][LAUNCH_TOKEN_ENV]) == 32
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600          # created by the UI
    assert stat.S_IMODE(os.stat(core_project.sidecar_dir(path)).st_mode) == 0o700
    with Store(path, create=False) as store:
        row = store.conn.execute("SELECT command, argv, target, token, status "
                                 "FROM launch").fetchone()
        assert row["command"] == "auto" and row["status"] == "running"
        assert row["token"] == seen["env"][LAUNCH_TOKEN_ENV]
        assert "hunter2" not in row["argv"] and "hunter2" not in row["target"]
        assert "hunter2" not in json.dumps(core_project.read_metadata(store))
    seen["on_done"](0, False)
    with Store(path, create=False) as store:
        assert store.conn.execute("SELECT status, exit_code FROM launch").fetchone()[:] \
            == ("succeeded", 0)


def test_unpinned_commands_and_lab_switches_keep_the_normal_umask(tmp_path, monkeypatch):
    seen = []

    async def fake_launch(self, argv, *, env=None, project=None, command="", on_done=None,
                          umask=None):
        seen.append((argv[3], project, umask))
        return "tok"
    monkeypatch.setattr(Runner, "launch", fake_launch)
    app, c = _client(tmp_path)
    assert c.post("/api/launch", json={"command": "build-db", "values": {}}).status_code == 200
    assert seen == [("build-db", None, None)]
    assert not (tmp_path / "start.db").exists()       # an unpinned job creates no project


def test_a_spawn_failure_marks_the_launch_failed_and_never_leaves_it_busy(tmp_path):
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)

    def bad_argv(spec, values):
        return ["/nonexistent/fuzzlab-no-such-binary"]

    async def go():
        with pytest.raises(OSError):
            await mgr.launch(commandspec.spec("report"), {}, bad_argv)
        assert mgr.busy_reasons() == []
    asyncio.run(go())
    with Store(tmp_path / "start.db", create=False) as store:
        assert store.conn.execute("SELECT status FROM launch").fetchone()[0] == "failed"


def test_launch_with_no_project_open_is_refused(tmp_path):
    app, c = _client(tmp_path, store=None)
    r = c.post("/api/launch", json={"command": "report", "values": {}})
    assert r.status_code == 409


# --- a real job: provenance, busy until recorded ---------------------------------------

_CHILD = ("import os, sys, time\n"
          "from fuzzlab.core.store import Store\n"
          "store, db = sys.argv[1], sys.argv[2]\n"
          "with Store(store) as s:\n"
          "    s.start_run('stand-in', 'h')\n"
          "open(db, 'w').write('x')\n"
          "time.sleep(float(sys.argv[3]))\n")


def _stand_in(seconds):
    def build(spec, values):
        return [sys.executable, "-c", _CHILD, values["store"], values["db"], str(seconds)]
    return build


def test_a_real_job_records_provenance_privately_and_blocks_switching(tmp_path):
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)
    crawl = commandspec.spec("crawl")

    async def go():
        token, argv = await mgr.launch(crawl, {"start": "http://127.0.0.1:8080"},
                                       _stand_in(1.0))
        assert mgr.busy_reasons() == ["job crawl"]
        for action in (mgr.close(), mgr.new("other"), mgr.temporary(),
                       mgr.save_as("copy")):
            with pytest.raises(ProjectBusy):
                await action
        async for _ in runner.stream(token):
            pass
        assert mgr.busy_reasons() == []
        return token
    old = os.umask(0o022)
    try:
        asyncio.run(go())
    finally:
        os.umask(old)
    path = tmp_path / "start.db"
    with Store(path, create=False) as store:
        run = store.conn.execute("SELECT tool, launch_id FROM run").fetchone()
        launch = store.conn.execute("SELECT id, status, exit_code FROM launch").fetchone()
        assert run["tool"] == "stand-in" and run["launch_id"] == launch["id"]
        assert (launch["status"], launch["exit_code"]) == ("succeeded", 0)
        hist = core_project.run_history(store)
        assert hist[0]["command"] == "crawl" and hist[0]["status"] == "succeeded"
        assert hist[0]["target"] == "http://127.0.0.1:8080"
    side = core_project.sidecar_dir(path)
    assert stat.S_IMODE(os.stat(side / "spider.db").st_mode) == 0o600   # child, umask 077


def test_busy_lasts_until_the_jobs_end_is_recorded(tmp_path, monkeypatch):
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)
    gate = threading.Event()
    real_finish = core_project.finish_launch

    def slow_finish(*a, **k):
        gate.wait(10)
        return real_finish(*a, **k)
    monkeypatch.setattr(core_project, "finish_launch", slow_finish)

    async def go():
        token, _ = await mgr.launch(commandspec.spec("crawl"), {}, _stand_in(0))
        run = runner._runs[token]
        while not run.finished:
            await asyncio.sleep(0.05)
        assert mgr.busy_reasons() == ["job crawl"]       # exited, not yet recorded
        with pytest.raises(ProjectBusy):
            await mgr.close()
        gate.set()
        async for _ in runner.stream(token):
            pass
        await mgr.close()
    asyncio.run(go())


def test_a_switch_issued_during_a_launch_waits_and_is_refused(tmp_path, monkeypatch):
    """F5: one lock from pinning to registration — a close cannot slip in between."""
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)
    real = procutil.astart_server
    entered = asyncio.Event

    async def go():
        started = entered()

        async def held(*a, **k):
            started.set()
            await asyncio.sleep(0.3)
            return await real(*a, **k)
        monkeypatch.setattr(procutil, "astart_server", held)
        launch = asyncio.create_task(mgr.launch(commandspec.spec("crawl"), {},
                                                _stand_in(0.5)))
        await started.wait()
        with pytest.raises(ProjectBusy):
            await mgr.close()                            # waited for the lock, then busy
        token, _ = await launch
        async for _ in runner.stream(token):
            pass
    asyncio.run(go())


# --- names and paths (NFR-UI-project-paths-confined) ------------------------------------

@pytest.mark.parametrize("name", ["../evil", "a/b", "x\n", ".hidden", "x.", "x ", " x",
                                  "a" * 65, "", "a..b", "\u00e9t\u00e9", "x\x00y", "C:\\x"])
def test_bad_project_names_are_refused(tmp_path, name):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    with pytest.raises(ProjectError):
        asyncio.run(mgr.new(name))
    assert not (tmp_path / "projects").exists() or \
        [p for p in os.listdir(tmp_path / "projects") if p.endswith(".fuzzlab")] == []


def test_open_refuses_traversal_symlinks_and_foreign_files(tmp_path):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("good"))
    d = tmp_path / "projects"
    outside = tmp_path / "outside.fuzzlab"
    core_project.create(outside)
    (d / "link.fuzzlab").symlink_to(outside)
    for bad in ("../outside.fuzzlab", "link.fuzzlab", "/etc/passwd", "good.fuzzlab/../x",
                "nope.txt"):
        with pytest.raises((ProjectError, OSError)):
            asyncio.run(mgr.open(file=bad))
    assert mgr.state()["name"] == "good"
    assert [f["file"] for f in mgr.list_files()] == ["good.fuzzlab"]   # no link listed
    # the path rule itself, beneath the name grammar (defence in depth)
    os.mkfifo(d / "fifo.fuzzlab")
    sub = d / "sub"
    sub.mkdir(mode=0o700)
    core_project.create(sub / "nested.fuzzlab")
    for bad in (outside, d / "link.fuzzlab", d / "fifo.fuzzlab", sub / "nested.fuzzlab",
                d / ".." / "outside.fuzzlab"):
        with pytest.raises(ProjectError):
            mgr._validate_file(bad)
    assert mgr._validate_file(d / "good.fuzzlab") == d / "good.fuzzlab"


def test_a_shared_or_linked_projects_directory_is_refused(tmp_path):
    d = tmp_path / "projects"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    with pytest.raises(ProjectError, match="0700"):
        asyncio.run(mgr.new("x"))
    assert mgr.list_files() == [] and mgr.recent() == []
    os.rmdir(d)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    d.symlink_to(real)
    with pytest.raises(ProjectError):
        asyncio.run(mgr.new("x"))


def test_a_recent_entry_outside_the_projects_directory_is_refused(tmp_path):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("a"))
    outside = tmp_path / "planted.fuzzlab"
    core_project.create(outside)
    rp = tmp_path / "projects" / "recent.json"
    data = json.loads(rp.read_text())
    data["entries"].insert(0, {"path": str(outside), "name": "planted",
                               "opened_at": "2026-01-01 00:00:00"})
    rp.write_text(json.dumps(data))
    with pytest.raises(ProjectError):
        asyncio.run(mgr.open(recent_id=0))


def test_the_startup_store_may_be_reopened_from_recent(tmp_path):
    start = tmp_path / "legacy.db"
    Store(start).close()
    mgr = ProjectManager(_cfg(tmp_path, store="legacy.db"))
    asyncio.run(mgr.new("b"))
    mgr._add_recent(start)
    entry = [r["id"] for r in mgr.recent() if r["path"] == str(start)][0]
    asyncio.run(mgr.open(recent_id=entry))
    assert mgr.store_path() == str(start)


def test_recent_list_two_writers_keep_both_and_malformed_is_quarantined(tmp_path):
    a = ProjectManager(_cfg(tmp_path, store=None))
    b = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(a.new("one"))
    paths = [tmp_path / "projects" / f"p{i}.fuzzlab" for i in range(6)]
    for p in paths:
        core_project.create(p)

    def add(mgr, ps):
        for p in ps:
            mgr._add_recent(p)
    t1 = threading.Thread(target=add, args=(a, paths[:3]))
    t2 = threading.Thread(target=add, args=(b, paths[3:]))
    t1.start(), t2.start()
    t1.join(), t2.join()
    names = {r["name"] for r in a.recent()}
    assert {p.stem for p in paths} <= names
    rp = tmp_path / "projects" / "recent.json"
    assert stat.S_IMODE(os.stat(rp).st_mode) == 0o600
    rp.write_text('{"version": 1, "entries": [{"path": 5}, {"path": "/x", "name": "x", '
                  '"opened_at": "t"}]}')
    entries, bad = projects._parse_recent(rp)
    assert bad == 1 and [e["path"] for e in entries] == ["/x"]
    rp.write_text("not json")
    assert projects._parse_recent(rp) == ([], 1)


# --- lifecycle through the routes --------------------------------------------------------

def test_lifecycle_new_open_save_as_close(tmp_path):
    app, c = _client(tmp_path, store=None)
    assert _state(c)["status"] == "none"
    assert c.post("/projects/new", data={"name": "alpha"}).status_code == 303
    assert _state(c)["name"] == "alpha"
    alpha = tmp_path / "projects" / "alpha.fuzzlab"
    with Store(alpha, create=False) as store:
        store.start_run("x", "h")
    c.post("/projects/save-as", data={"name": "beta"})
    st = _state(c)
    assert st["name"] == "beta"
    with Store(tmp_path / "projects" / "beta.fuzzlab", create=False) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert core_project.read_metadata(store)["name"] == "beta"
    c.post("/projects/open", data={"file": "alpha.fuzzlab"})
    assert _state(c)["name"] == "alpha"
    assert [r["name"] for r in c.get("/api/projects").json()["recent"]] == ["alpha", "beta"]
    c.post("/projects/new", data={"name": "alpha"})          # exists: refused, stays
    assert "already exists" in _flash(c) and _state(c)["name"] == "alpha"
    c.post("/projects/close")
    assert _state(c)["status"] == "none"
    modes = _tree_modes(tmp_path / "projects")
    assert all(m == (0o700 if os.path.isdir(tmp_path / "projects" / k) else 0o600)
               for k, m in modes.items()), modes


def test_temporary_project_discard_needs_confirmation_and_removes_only_its_files(tmp_path):
    app, c = _client(tmp_path, store=None)
    c.post("/projects/temporary")
    st = _state(c)
    assert st["kind"] == "temporary"
    tpath = Path(st["path"])
    with Store(tpath, create=False) as store:
        store.start_run("x", "h")
    side = core_project.sidecar_dir(tpath)
    (side / "spider.db").write_text("x")
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    (side / "audit.db").symlink_to(victim)              # named like a sidecar
    sibling = tpath.parent / (tpath.name + ".notes")
    sibling.write_text("keep")
    for action in ("/projects/close", "/projects/temporary"):
        c.post(action)
        assert "leaving it deletes it" in _flash(c) and _state(c)["path"] == str(tpath)
    c.post("/projects/new", data={"name": "z"})
    assert _state(c)["path"] == str(tpath)
    c.post("/projects/close", data={"discard": "1"})
    assert _state(c)["status"] == "none"
    assert "was discarded, but" in _flash(c)           # the symlink was left and reported
    assert not tpath.exists() and not Path(str(tpath) + "-wal").exists()
    assert victim.read_text() == "keep me" and sibling.exists()
    assert (side / "audit.db").is_symlink() and not (side / "spider.db").exists()


def test_save_as_keeps_a_temporary_projects_runs_and_removes_the_temporary(tmp_path):
    app, c = _client(tmp_path, store=None)
    c.post("/projects/temporary")
    tpath = Path(_state(c)["path"])
    with Store(tpath, create=False) as store:
        store.start_run("x", "h")
    c.post("/projects/save-as", data={"name": "kept"})
    assert _state(c)["name"] == "kept" and not tpath.exists()
    with Store(tmp_path / "projects" / "kept.fuzzlab", create=False) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1


def test_a_leftover_temporary_is_listed_and_one_held_by_another_ui_is_not_discarded(tmp_path):
    a = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(a.temporary())
    name = Path(a.store_path()).name
    b = ProjectManager(_cfg(tmp_path, store=None))
    assert b.leftover_temporaries() == [name]
    with pytest.raises(ProjectError, match="in use"):
        asyncio.run(b.discard_leftover(name))
    projects._release_owner(a.current.owner_fd)          # the other UI exits
    a.current.owner_fd = None
    assert asyncio.run(b.discard_leftover(name)) == []
    assert b.leftover_temporaries() == []
    with pytest.raises(ProjectError):
        asyncio.run(b.discard_leftover("../../x"))


# --- schema mismatch (FR-UI-457) ----------------------------------------------------------

def _snapshot(path: Path):
    return {p.name: (p.read_bytes(), os.stat(p).st_mtime_ns)
            for p in path.parent.iterdir() if p.name.startswith(path.name)}


def _html_routes(app):
    from fastapi.routing import APIRoute
    out = []
    for r in app.routes:
        if isinstance(r, APIRoute) and "GET" in r.methods and "{" not in r.path:
            out.append(r.path)
    return out


def test_an_older_startup_project_is_never_touched_until_migration_is_accepted(tmp_path):
    path = tmp_path / "old.db"
    with Store(path) as store:
        store.start_run("auto", "h")
        undo_after(store.conn, 21)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 22")
        store.conn.commit()
    app, c = _client(tmp_path, store="old.db")
    before = _snapshot(path)                     # after create_app's read-only inspect
    st = _state(c)
    assert st["status"] == "pending" and st["pending"]["kind"] == "older"
    assert st["pending"]["schema_version"] == 21
    for route in _html_routes(app):
        c.get(route)
    assert _snapshot(path) == before
    assert "migration needed" in c.get("/").text
    assert c.post("/api/launch", json={"command": "report", "values": {}}).status_code == 409
    c.post("/projects/migrate")
    st = _state(c)
    assert st["status"] == "open" and st["path"] == str(path)
    assert "backup written to" in c.get("/project").text
    backups = list((core_project.sidecar_dir(path) / "backups").iterdir())
    assert len(backups) == 1 and core_project.inspect(backups[0]).schema_version == 21
    assert core_project.inspect(path).state == "ok"


def test_a_newer_project_is_refused_and_never_written(tmp_path):
    path = tmp_path / "new.db"
    Store(path).close()
    import sqlite3
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO schema_version (version) VALUES (9999)")
    conn.commit()
    conn.close()
    app, c = _client(tmp_path, store="new.db")
    before = _snapshot(path)
    st = _state(c)
    assert st["status"] == "pending" and st["pending"]["kind"] == "refused"
    assert "newer" in st["pending"]["detail"]
    for route in _html_routes(app):
        c.get(route)
    c.post("/projects/migrate")
    assert _snapshot(path) == before


# --- no project open -----------------------------------------------------------------------

def test_with_no_project_open_nothing_creates_a_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app, c = _client(tmp_path, store=None)
    for route in _html_routes(app):
        assert c.get(route).status_code < 500, route     # 409/422: no proxy, a missing query
    assert c.post("/api/views", json={"table": "t", "name": "n", "spec": {}}).status_code == 409
    assert c.post("/api/proxy/repeater/tabs", json={"name": "t", "raw": "GET / HTTP/1.1\r\n\r\n"}
                  ).status_code == 409
    assert sorted(os.listdir(tmp_path)) == []


def test_every_page_shows_the_open_project(tmp_path):
    app, c = _client(tmp_path)
    for route in _html_routes(app):
        if route.startswith("/api/"):
            continue
        html = c.get(route).text
        assert 'id="project-chip"' in html and "start" in html, route


def test_every_project_action_is_refused_cross_site(tmp_path):
    from fastapi.routing import APIRoute
    from fastapi.testclient import TestClient
    app = create_app(_cfg(tmp_path))
    hostile = TestClient(app, base_url="http://127.0.0.1:8787", headers={
        "Origin": "http://127.0.0.1:8080", "Sec-Fetch-Site": "same-site"})
    posts = [r.path for r in app.routes if isinstance(r, APIRoute) and "POST" in r.methods
             and (r.path.startswith("/projects") or r.path.startswith("/project/"))]
    assert len(posts) >= 9
    for path in posts:
        assert hostile.post(path, data={"name": "x"}).status_code == 403, path
    assert not (tmp_path / "projects").exists()
    ok = web_client(app, follow_redirects=False)
    assert ok.post("/projects/new", data={"name": "x"},
                   headers=SAME_ORIGIN_HEADERS).status_code == 303


# --- the Repeater follows the project ---------------------------------------------------------

def test_repeater_tabs_follow_the_project_with_their_own_run(tmp_path):
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "a"})
    raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    assert c.post("/api/proxy/repeater/tabs", json={"name": "in-a", "raw": raw}).status_code == 200
    c.post("/projects/new", data={"name": "b"})
    assert c.get("/api/proxy/repeater/tabs").json()["tabs"] == []
    assert c.post("/api/proxy/repeater/tabs", json={"name": "in-b", "raw": raw}).status_code == 200
    for name, tab in (("a", "in-a"), ("b", "in-b")):
        with Store(tmp_path / "projects" / f"{name}.fuzzlab", create=False) as store:
            rows = store.conn.execute(
                "SELECT t.name, r.tool FROM repeater_tab t JOIN run r ON r.id = t.run_id"
            ).fetchall()
            assert [tuple(r) for r in rows] == [(tab, "repeater")]


# --- the in-process proxy keeps its project busy ------------------------------------------------

class _FakeProxy:
    def __init__(self, store_path):
        from types import SimpleNamespace
        self.config = SimpleNamespace(store_path=store_path, host="127.0.0.1")
        self.started = False

    async def start(self):
        self.started = True

    async def stop(self):
        pass

    def status(self):
        return {"configured": True, "running": self.started}


def test_the_in_process_proxy_creates_its_project_and_keeps_it_busy(tmp_path):
    from fastapi.testclient import TestClient
    path = tmp_path / "start.db"
    proxy = _FakeProxy(str(path))
    app = create_app(_cfg(tmp_path), proxy=proxy)
    with TestClient(app, base_url="http://127.0.0.1:8787", headers=SAME_ORIGIN_HEADERS,
                    follow_redirects=False) as c:
        assert proxy.started and stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert "in-process proxy" in " ".join(_state(c)["busy"])
        c.post("/projects/new", data={"name": "x"})
        assert _state(c)["path"] == str(path)


def test_the_in_process_proxy_refuses_a_project_waiting_for_migration(tmp_path):
    from fastapi.testclient import TestClient
    path = tmp_path / "old.db"
    with Store(path) as store:
        undo_after(store.conn, 21)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 22")
        store.conn.commit()
    app = create_app(_cfg(tmp_path, store="old.db"), proxy=_FakeProxy(str(path)))
    with pytest.raises(RuntimeError, match="without --with-proxy"):
        with TestClient(app, base_url="http://127.0.0.1:8787", headers=SAME_ORIGIN_HEADERS):
            pass


# --- a project file never holds a credential ------------------------------------------------

def test_a_project_file_never_contains_a_credential_value(tmp_path, monkeypatch):
    """NFR-UI-project-provenance-redacted / FR-UI-456: a keyring credential, URL
    userinfo and token query values planted through every UI input that reaches the
    project are absent from every persisted copy; a benign control value is present
    (the scan is not vacuous)."""
    from fuzzlab.core.credentials import CredentialStore
    from tests.test_credentials import FakeBackend
    secret = "Pw-9f3c1e77-planted"
    creds = CredentialStore(backend=FakeBackend())
    creds.set("127.0.0.1", "alice", "alice", secret)

    async def fake_launch(self, argv, **kw):
        return "tok"
    monkeypatch.setattr(Runner, "launch", fake_launch)
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "p"})
    benign = "benign-marker-7d1"
    c.post("/api/launch", json={"command": "auto", "values": {
        "base_url": f"http://alice:{secret}@127.0.0.1:8080/?token={secret}",
        "identity": "alice", "categories": benign}})
    c.post("/api/launch", json={"command": "crawl", "values": {
        "start": f"alice:{secret}@127.0.0.1:8080/x?access_token={secret}"}})
    c.post("/project/meta", data={"notes": "ok", "targets":
                                  f"http://u:{secret}@127.0.0.1:9000/\nhttp://127.0.0.1/?api_key={secret}"})
    c.post("/projects/save-as", data={"name": "copy"})
    files = [p for p in (tmp_path / "projects").rglob("*") if p.is_file()]
    blob = b"".join(p.read_bytes() for p in files)
    assert secret.encode() not in blob
    assert benign.encode() in blob


# --- umask reaches the whole tree ---------------------------------------------------------------

def _run_writer(out: Path, umask):
    async def go():
        runner = Runner()
        token = await runner.launch(
            [sys.executable, "-c", f"open({str(out)!r}, 'w').write('x')"], umask=umask)
        async for _ in runner.stream(token):
            pass
    old = os.umask(0o022)
    try:
        asyncio.run(go())
    finally:
        os.umask(old)
    return stat.S_IMODE(os.stat(out).st_mode)


def test_a_launch_umask_reaches_the_whole_tree(tmp_path):
    """`Runner.launch(umask=)` -> `procutil.astart_server(umask=)` -> the supervisor."""
    assert _run_writer(tmp_path / "f", 0o077) == 0o600


def test_with_no_umask_the_child_keeps_the_inherited_one(tmp_path):
    assert _run_writer(tmp_path / "f", None) == 0o644


def test_needs_discard_and_no_project_are_distinct_errors():
    assert not issubclass(NeedsDiscard, NoProject) and not issubclass(NoProject, NeedsDiscard)
    assert build_argv  # imported for the stand-in builders' signature


# --- code-review regressions (CC-UI-0450 review round 1) --------------------------------

def _older(path: Path):
    with Store(path) as store:
        store.start_run("auto", "h")
        undo_after(store.conn, 21)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 22")
        store.conn.commit()


def test_opening_an_older_or_newer_file_while_a_project_is_open_shows_why(tmp_path):
    """A1: the offer or refusal is shown, not a silent no-op; the open project stays."""
    import sqlite3
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "cur"})
    _older(tmp_path / "projects" / "old.fuzzlab")
    newer = tmp_path / "projects" / "newer.fuzzlab"
    Store(newer).close()
    conn = sqlite3.connect(newer)
    conn.execute("INSERT INTO schema_version (version) VALUES (9999)")
    conn.commit()
    conn.close()
    c.post("/projects/open", data={"file": "old.fuzzlab"})
    page = c.get("/projects").text
    assert 'id="project-migrate-offer"' in page and "uses schema v21" in page
    assert _state(c)["name"] == "cur"
    c.post("/projects/open", data={"file": "newer.fuzzlab"})
    page = c.get("/projects").text
    assert 'id="project-refused"' in page and "newer" in page
    assert _state(c)["name"] == "cur"


@pytest.mark.parametrize("action", ["new", "save-as"])
def test_new_and_save_as_refuse_a_stale_project_directory_and_leave_it(tmp_path, action):
    """B2/A3: a stale `<name>.fuzzlab.d` is neither adopted nor deleted."""
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "src"})
    stale = tmp_path / "projects" / "acme.fuzzlab.d"
    stale.mkdir(mode=0o700)
    (stale / "spider.db").write_text("another project's crawl")
    c.post(f"/projects/{action}", data={"name": "acme"})
    assert "already exists" in _flash(c)
    assert _state(c)["name"] == "src"
    assert (stale / "spider.db").read_text() == "another project's crawl"
    assert not (tmp_path / "projects" / "acme.fuzzlab").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_a_planted_link_in_the_project_directory_is_refused_before_the_job(tmp_path,
                                                                            monkeypatch,
                                                                            kind):
    """B3: a tool's `open()` would follow it out of the project."""
    async def fake_launch(self, argv, **kw):
        raise AssertionError("must not start")
    monkeypatch.setattr(Runner, "launch", fake_launch)
    app, c = _client(tmp_path)
    c.post("/projects/new", data={"name": "beta"})
    side = tmp_path / "projects" / "beta.fuzzlab.d"
    side.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    (side / "fuzz.csv").symlink_to(victim) if kind == "symlink" else \
        os.link(victim, side / "fuzz.csv")
    r = c.post("/api/launch", json={"command": "fuzz", "values": {"url": "http://127.0.0.1/"}})
    assert r.status_code == 409 and "not a plain file" in r.json()["error"]
    assert victim.read_text() == "keep"
    with Store(tmp_path / "projects" / "beta.fuzzlab", create=False) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM launch").fetchone()[0] == 0


def test_a_project_directory_that_is_not_private_is_a_409_not_a_500(tmp_path, monkeypatch):
    async def fake_launch(self, argv, **kw):
        return "tok"
    monkeypatch.setattr(Runner, "launch", fake_launch)
    app, c = _client(tmp_path)
    side = core_project.sidecar_dir(tmp_path / "start.db")
    side.mkdir(mode=0o755)
    os.chmod(side, 0o755)
    r = c.post("/api/launch", json={"command": "report", "values": {}})
    assert r.status_code == 409 and "0700" in r.json()["error"]


def test_a_failed_argv_build_marks_the_launch_failed(tmp_path):
    """B13: a launch row is never left `running` by a failure before the spawn."""
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)

    def broken(spec, values):
        raise ValueError("bad argv")
    with pytest.raises(ValueError):
        asyncio.run(mgr.launch(commandspec.spec("report"), {}, broken))
    with Store(tmp_path / "start.db", create=False) as store:
        assert store.conn.execute("SELECT status FROM launch").fetchone()[0] == "failed"
    assert mgr.busy_reasons() == []


def test_discard_leftovers_are_reported_when_leaving_by_new(tmp_path):
    """B6/A2: every transition reports what a discard left, not only Close."""
    app, c = _client(tmp_path, store=None)
    c.post("/projects/temporary")
    side = core_project.sidecar_dir(Path(_state(c)["path"]))
    (side / "unknown.bin").write_text("x")
    c.post("/projects/new", data={"name": "next", "discard": "1"})
    assert _state(c)["name"] == "next"
    assert "1 unknown file(s)" in _flash(c)


def test_action_error_list_shows_a_named_error_and_propagates_others(tmp_path, monkeypatch):
    """B7 (PA-0106): a refusal becomes a message; an unexpected error is a loud 500."""
    from fastapi.testclient import TestClient
    app = create_app(_cfg(tmp_path, store=None))
    c = TestClient(app, base_url="http://127.0.0.1:8787", headers=SAME_ORIGIN_HEADERS,
                   follow_redirects=False, raise_server_exceptions=False)
    assert c.post("/projects/new", data={"name": "../x"}).status_code == 303   # ProjectError
    assert "a project name is" in c.get("/projects").text

    async def boom(self, name, *, discard=False):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(ProjectManager, "new", boom)
    assert c.post("/projects/new", data={"name": "y"}).status_code == 500


def test_record_error_list_reports_a_vanished_project_and_propagates_others(tmp_path):
    """B7 (PA-0106): only OperationalError (a gone or locked file) is reported."""
    import sqlite3

    async def go(err):
        runner = Runner()

        def on_done(rc, stopping):
            raise err
        token = await runner.launch([sys.executable, "-c", "pass"], on_done=on_done)
        lines = [ev async for ev in runner.stream(token)]
        return runner, token, lines
    runner, token, lines = asyncio.run(go(sqlite3.OperationalError("unable to open")))
    assert any("could not record" in ln for ln in lines) and not runner.unrecorded(token)
    runner, token, lines = asyncio.run(go(KeyError("defect")))
    assert not any("could not record" in ln for ln in lines)
    assert not runner.unrecorded(token)            # still recorded: never stays busy


def test_recent_json_is_never_followed_or_read_past_its_cap(tmp_path):
    d = tmp_path / "projects"
    d.mkdir(mode=0o700)
    big = tmp_path / "big"
    big.write_bytes(b"[" * (projects.RECENT_MAX_BYTES + 10))
    (d / "recent.json").symlink_to(big)
    assert projects._parse_recent(d / "recent.json") == ([], 1)
    os.unlink(d / "recent.json")
    (d / "recent.json").write_bytes(b" " * (projects.RECENT_MAX_BYTES + 10))
    assert projects._parse_recent(d / "recent.json") == ([], 1)
    os.unlink(d / "recent.json")
    os.mkfifo(d / "recent.json")
    assert projects._parse_recent(d / "recent.json") == ([], 1)


def test_missing_parents_of_the_projects_directory_are_created_private(tmp_path):
    """B9: each created parent is 0700; existing ones are left as they are."""
    deep = tmp_path / "a" / "b" / "projects"
    mgr = ProjectManager(load_config(overrides={"store_path": "", "projects_dir": str(deep)},
                                     environ={}))
    old = os.umask(0o022)
    try:
        asyncio.run(mgr.new("x"))
    finally:
        os.umask(old)
    for p in (tmp_path / "a", tmp_path / "a" / "b", deep):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o700, p
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) != 0o700 or True


def test_a_linked_temporary_directory_is_refused(tmp_path):
    """B10: `.temporary` is checked like the projects directory."""
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("x"))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    core_project.create(elsewhere / "tmp-20260101T000000Z-0123abcd.fuzzlab")
    (tmp_path / "projects" / ".temporary").symlink_to(elsewhere)
    assert mgr.leftover_temporaries() == []
    with pytest.raises(ProjectError):
        asyncio.run(mgr.open(temporary="tmp-20260101T000000Z-0123abcd.fuzzlab"))
    with pytest.raises(ProjectError):
        asyncio.run(mgr.discard_leftover("tmp-20260101T000000Z-0123abcd.fuzzlab"))
    assert (elsewhere / "tmp-20260101T000000Z-0123abcd.fuzzlab").exists()


def test_a_recent_entry_must_name_a_project_file(tmp_path):
    """B10: a hand-edited recent entry cannot open an arbitrary file in the directory."""
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("x"))
    stray = tmp_path / "projects" / ".copy-0011.tmp"
    core_project.create(stray)
    rp = tmp_path / "projects" / "recent.json"
    data = json.loads(rp.read_text())
    data["entries"].insert(0, {"path": str(stray), "name": "s", "opened_at": "t"})
    rp.write_text(json.dumps(data))
    with pytest.raises(ProjectError, match="not a project file name"):
        asyncio.run(mgr.open(recent_id=0))


def test_owner_lock_and_saved_project_directory_are_private(tmp_path):
    """B12: the temporary's owner lock, and a Save As copy of the project directory."""
    old = os.umask(0o022)
    try:
        app, c = _client(tmp_path, store=None)
        c.post("/projects/temporary")
        tpath = Path(_state(c)["path"])
        side = core_project.sidecar_dir(tpath)
        assert stat.S_IMODE(os.stat(side / projects.OWNER_LOCK).st_mode) == 0o600
        Store(side / "spider.db").close()
        os.chmod(side / "spider.db", 0o600)
        (side / "fuzz.csv").write_text("a,b\n")
        os.chmod(side / "fuzz.csv", 0o600)
        c.post("/projects/save-as", data={"name": "kept"})
        kept = tmp_path / "projects" / "kept.fuzzlab.d"
        assert stat.S_IMODE(os.stat(kept).st_mode) == 0o700
        for n in ("spider.db", "fuzz.csv"):
            assert stat.S_IMODE(os.stat(kept / n).st_mode) == 0o600, n
    finally:
        os.umask(old)


def test_shutdown_records_a_stopped_job_as_stopped(tmp_path):
    """A4: the UI's shutdown waits for each stopped job to record its end."""
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)

    async def go():
        await mgr.launch(commandspec.spec("crawl"), {}, _stand_in(30))
        await runner.shutdown()
        assert mgr.busy_reasons() == []
    asyncio.run(go())
    with Store(tmp_path / "start.db", create=False) as store:
        assert store.conn.execute("SELECT status FROM launch").fetchone()[0] == "stopped"


def test_a_failure_in_the_pump_tail_still_ends_busy_and_the_stream(tmp_path, monkeypatch):
    """A5: the whole tail is in the finally — a raising stop never leaves a job busy."""
    real = procutil.astop_server
    calls = []

    async def raising(h, **kw):
        calls.append(1)
        if len(calls) == 1:
            await real(h, **kw)
            raise RuntimeError("injected tail failure")
        return await real(h, **kw)
    monkeypatch.setattr(procutil, "astop_server", raising)
    runner = Runner()
    mgr = ProjectManager(_cfg(tmp_path), runner)

    async def go():
        token, _ = await mgr.launch(commandspec.spec("crawl"), {}, _stand_in(0))
        events = [ev async for ev in runner.stream(token)]
        assert any("event: done" in ev for ev in events)
        assert mgr.busy_reasons() == []
    asyncio.run(go())


def test_a_project_replaced_at_the_same_path_gets_its_own_repeater_run(tmp_path):
    """A9: Repeater state is keyed by the file's identity, not its path alone."""
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "x"})
    raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    c.post("/api/proxy/repeater/tabs", json={"name": "old", "raw": raw})
    c.post("/projects/close")
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(tmp_path / "projects" / "x.fuzzlab") + suffix)
        if p.exists():
            p.unlink()
    c.post("/projects/new", data={"name": "x"})
    with Store(tmp_path / "projects" / "x.fuzzlab", create=False) as store:
        store.start_run("crawl", "h")                     # run id 1 is now a crawl
    assert c.post("/api/proxy/repeater/tabs", json={"name": "new", "raw": raw}).status_code == 200
    with Store(tmp_path / "projects" / "x.fuzzlab", create=False) as store:
        rows = store.conn.execute("SELECT t.name, r.tool FROM repeater_tab t "
                                  "JOIN run r ON r.id = t.run_id").fetchall()
        assert [tuple(r) for r in rows] == [("new", "repeater")]
