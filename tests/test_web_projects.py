"""Project files in the web UI (CC-UI-0450; FR-UI-450..457; NFR-UI-project-private,
NFR-UI-project-paths-confined, NFR-UI-project-provenance-redacted,
NFR-UI-project-switch-safe)."""

from __future__ import annotations

import ast
import asyncio
import json
import sqlite3
import re
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
_CREATORS = {"create": {"_create_locked"},
             "copy_to": {"_save_as", "_copy_sidecars", "_snapshot"}}


def _refname(node):
    return node.id if isinstance(node, ast.Name) else \
        node.attr if isinstance(node, ast.Attribute) else None


def _creating_opens(source: str, filename: str) -> list[str]:
    """Code in ``source`` that may open a store and create its file, or create a project
    file outside its allowed function:

    - a call of ``Store`` / ``open_store`` / ``connect`` (under any import alias) without
      ``create=False``, and any ``sqlite3.connect`` (under any module alias);
    - any other use of an opener name — assigned, passed, stored, defaulted, subclassed,
      reached by ``getattr`` — except as the direct callee or in an annotation;
    - ``create`` / ``copy_to`` of ``fuzzlab.core.project`` (by any module alias, or
      imported by name) called outside the functions allowed to.
    Code review B, rounds 1-2 (PA-0034(2)): every shape is a synthetic offender below."""
    tree = ast.parse(source)
    aliases, sqlite_mods = set(_OPENERS), {"sqlite3"}
    project_mods, creator_names = {"core_project"}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name in _OPENERS:
                    aliases.add(a.asname or a.name)
                if node.module == "fuzzlab.core" and a.name == "project":
                    project_mods.add(a.asname or a.name)
                if node.module == "fuzzlab.core.project" and a.name in _CREATORS:
                    creator_names[a.asname or a.name] = a.name
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "sqlite3":
                    sqlite_mods.add(a.asname or a.name)
                if a.name == "fuzzlab.core.project" and a.asname:
                    project_mods.add(a.asname)
    annotations = set()
    for node in ast.walk(tree):
        for ann in ([node.returns] if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    else []) + ([node.annotation] if isinstance(node, (ast.arg, ast.AnnAssign))
                                else []):
            if ann is not None:
                annotations.update(id(n) for n in ast.walk(ann))
    callee_ids = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    offenders = []

    def visit(node, func):
        for child in ast.iter_child_nodes(node):
            f = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                else func
            allowed = (filename, f) in _CREATE_ALLOWED
            if isinstance(child, ast.Call):
                name = _refname(child.func)
                is_sqlite = (isinstance(child.func, ast.Attribute) and
                             isinstance(child.func.value, ast.Name) and
                             child.func.value.id in sqlite_mods)
                no_create = any(k.arg == "create" and isinstance(k.value, ast.Constant)
                                and k.value.value is False for k in child.keywords)
                if (name in aliases or is_sqlite) and (is_sqlite or not no_create) \
                        and not allowed:
                    offenders.append(f"{filename}:{child.lineno} {name}(")
                if name == "getattr" and any(isinstance(a, ast.Constant) and
                                             a.value in _OPENERS | set(_CREATORS)
                                             for a in child.args):
                    offenders.append(f"{filename}:{child.lineno} getattr(…opener)")
                creator = None
                if isinstance(child.func, ast.Attribute) and name in _CREATORS and \
                        _refname(child.func.value) in project_mods:
                    creator = name
                elif isinstance(child.func, ast.Name) and child.func.id in creator_names:
                    creator = creator_names[child.func.id]
                if creator and f not in _CREATORS[creator]:
                    offenders.append(f"{filename}:{child.lineno} core project {creator}(")
            elif (isinstance(child, (ast.Name, ast.Attribute)) and
                  _refname(child) in aliases and id(child) not in callee_ids and
                  id(child) not in annotations and
                  isinstance(getattr(child, "ctx", None), ast.Load)):
                offenders.append(f"{filename}:{getattr(child, 'lineno', 0)} "
                                 f"{_refname(child)} used, not called")
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
    # code review B, round 2
    "from fuzzlab.core.project import create\ndef f(p):\n    create(p)\n",
    "from fuzzlab.core import project as cp\ndef f(p):\n    cp.create(p)\n",
    "from fuzzlab.core import project as cp\ndef f(a, b):\n    cp.copy_to(a, b)\n",
    "def f(p):\n    S: type = Store\n    return S(p)\n",
    "def f(p):\n    return (S := Store)(p)\n",
    "def f(p):\n    S, = (Store,)\n    return S(p)\n",
    "def f(p, S=Store):\n    return S(p)\n",
    "OPEN = {'s': Store}\n",
    "class X(Store):\n    pass\n",
    "def f(p):\n    return (lambda: Store)()(p)\n",
])
def test_the_creating_open_guard_catches_synthetic_offenders(bad):
    assert _creating_opens(bad, "x.py"), bad


def test_the_creating_open_guard_passes_a_no_create_open():
    good = ("def f(p):\n    return Store(p, create=False)\n"
            "def _create_locked(p):\n    return core_project.create(p)\n")
    assert _creating_opens(good, "x.py") == []


_RECORD_WRITE = __import__("re").compile(
    r"\b(?:INSERT(?:\s+OR\s+\w+)?\s*INTO|REPLACE\s*INTO|UPDATE(?:\s+OR\s+\w+)?"
    r"|DELETE\s*FROM)\s*(?:[\"`\[]?main[\"`\]]?\.)?[\"`\[]?(?:launch|project)\b",
    __import__("re").I)


def _sql_text(source: str) -> str:
    """``source`` with every string constant joined the way Python joins it (implicit
    concatenation, ``+``, f-string parts) and SQL comments removed, so a split or
    commented statement still reads as one (code review B, round 2)."""
    import re as _re
    parts = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(node.value)
        elif isinstance(node, ast.JoinedStr):
            parts.append("".join(v.value if isinstance(v, ast.Constant) else " " for v in
                                 node.values))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts.append("".join(n.value for n in ast.walk(node)
                                 if isinstance(n, ast.Constant) and isinstance(n.value, str)))
    text = "\n".join(parts)
    text = _re.sub(r"/\*.*?\*/", " ", text, flags=_re.S)
    return _re.sub(r"--[^\n]*", " ", text)


def _record_writers(source: str) -> bool:
    return bool(_RECORD_WRITE.search(_sql_text(source)))


def test_only_core_project_writes_the_project_record_tables():
    """PA-0100: every write to `launch`/`project` goes through `core.project`, whose
    writers redact through `redact_for_record`."""
    root = WEB.parent
    writers = sorted(str(p.relative_to(root)) for p in root.rglob("*.py")
                     if _record_writers(p.read_text()))
    # migrations.py: migration 23's post-step backfills `project.uuid` (PA-0105(2)).
    assert writers == ["core/migrations.py", "core/project.py"], writers
    for offender in ("UPDATE launch SET argv=?", "INSERT OR REPLACE INTO launch (a) VALUES (1)",
                     "REPLACE INTO project (id) VALUES (1)", 'UPDATE "launch" SET x=1',
                     "DELETE FROM launch", "update main.project set notes=''",
                     "INSERT INTO `project` (id) VALUES (1)", "INSERT/**/INTO launch (a)",
                     'INSERT INTO"launch"(a)'):
        assert _record_writers(repr(offender)), offender
    assert _record_writers('x = "INSERT INTO " "launch (a) VALUES (1)"')
    assert _record_writers('x = "INSERT INTO " + "launch (a)"')
    assert _record_writers('x = f"UPDATE {t} SET a=1; UPDATE project SET b=2"')
    for benign in ("SELECT id FROM launch WHERE token=?", "INSERT INTO run (launch_id)",
                   "CREATE TABLE IF NOT EXISTS launch ("):
        assert not _record_writers(repr(benign)), benign


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
    with pytest.raises(ProjectError, match="projects directory"):
        asyncio.run(mgr.open(recent_id=0, recent_path=str(outside)))
    with pytest.raises(ProjectError, match="the recent list changed"):
        asyncio.run(mgr.open(recent_id=0))               # the path is required too


def test_the_startup_store_may_be_reopened_from_recent(tmp_path):
    start = tmp_path / "legacy.db"
    Store(start).close()
    mgr = ProjectManager(_cfg(tmp_path, store="legacy.db"))
    asyncio.run(mgr.new("b"))
    mgr._add_recent(start)
    entry = [r["id"] for r in mgr.recent() if r["path"] == str(start)][0]
    asyncio.run(mgr.open(recent_id=entry, recent_path=str(start)))
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
    with pytest.raises(ProjectError, match="Tick"):
        asyncio.run(b.discard_leftover(name))                  # needs the confirmation
    with pytest.raises(ProjectError, match="in use"):
        asyncio.run(b.discard_leftover(name, confirm=True))
    projects._release_owner(a.current.owner_fd)          # the other UI exits
    a.current.owner_fd = None
    assert asyncio.run(b.discard_leftover(name, confirm=True)) == []
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
    planted = tmp_path / "planted.json"                 # small and valid: only the
    planted.write_text(json.dumps({"version": 1, "entries": [  # no-follow refuses it
        {"path": "/x.fuzzlab", "name": "x", "opened_at": "t"}]}))
    (d / "recent.json").symlink_to(planted)
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
    os.chmod(tmp_path, 0o755)                     # an existing parent is left as it is
    mgr2 = ProjectManager(load_config(overrides={
        "store_path": "", "projects_dir": str(tmp_path / "c" / "projects")}, environ={}))
    asyncio.run(mgr2.new("y"))
    assert stat.S_IMODE(os.stat(tmp_path).st_mode) == 0o755


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
        asyncio.run(mgr.discard_leftover("tmp-20260101T000000Z-0123abcd.fuzzlab",
                                         confirm=True))
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
        asyncio.run(mgr.open(recent_id=0, recent_path=str(stray)))


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
            raise procutil.ProcUtilError("injected tail failure")
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
    with Store(tmp_path / "start.db", create=False) as store:   # and the end is recorded
        assert store.conn.execute("SELECT status FROM launch").fetchone()[0] == "succeeded"


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



def test_a_replacement_holding_its_own_repeater_run_is_not_reused(tmp_path):
    """The file identity is what tells the projects apart (mutation-checked, round 3): the
    replacement also has a `repeater` run with the cached id, so the run-id re-check alone
    would reuse it; the old file is kept (moved away) so its inode is not recycled."""
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "x"})
    path = tmp_path / "projects" / "x.fuzzlab"
    raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    c.post("/api/proxy/repeater/tabs", json={"name": "old", "raw": raw})
    c.post("/projects/close")
    other = tmp_path / "other.fuzzlab"
    core_project.create(other)
    with Store(other, create=False) as store:
        foreign = store.start_run("repeater", "h")         # same id the cache holds
    kept = tmp_path / "kept"
    kept.mkdir()
    for suffix in ("", "-wal", "-shm"):
        if Path(str(path) + suffix).exists():
            os.rename(str(path) + suffix, str(kept / ("x.fuzzlab" + suffix)))
    os.rename(other, path)
    c.post("/projects/open", data={"file": "x.fuzzlab"})
    assert _state(c)["path"] == str(path)
    assert c.post("/api/proxy/repeater/tabs", json={"name": "new", "raw": raw}).status_code == 200
    with Store(path, create=False) as store:
        run_id = store.conn.execute(
            "SELECT run_id FROM repeater_tab WHERE name='new'").fetchone()[0]
    assert run_id != foreign


# --- code review round 2 (CC-UI-0450) ----------------------------------------------------

def test_stale_pages_and_bad_input_are_messages_not_500s(tmp_path):
    """A-r2-1: a file removed after the page rendered, a non-ASCII digit, a corrupt
    project database — each becomes a refusal message, never a 500."""
    from fastapi.testclient import TestClient
    app = create_app(_cfg(tmp_path, store=None))
    c = TestClient(app, base_url="http://127.0.0.1:8787", headers=SAME_ORIGIN_HEADERS,
                   follow_redirects=False, raise_server_exceptions=False)
    c.post("/projects/new", data={"name": "a"})
    c.post("/projects/new", data={"name": "b"})
    os.unlink(tmp_path / "projects" / "a.fuzzlab")
    assert c.post("/projects/open", data={"file": "a.fuzzlab"}).status_code == 303
    assert "no longer exists" in c.get("/projects").text
    assert c.post("/projects/open", data={"recent": "\u00b2"}).status_code == 303
    assert "no such recent project" in c.get("/projects").text
    side = tmp_path / "projects" / "b.fuzzlab.d"
    side.mkdir(mode=0o700)
    (side / "spider.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    os.chmod(side / "spider.db", 0o600)
    assert c.post("/projects/save-as", data={"name": "c"}).status_code == 303
    assert "save as failed" in c.get("/projects").text
    assert not (tmp_path / "projects" / "c.fuzzlab").exists()


def test_a_long_target_is_refused_before_any_launch_row(tmp_path, monkeypatch):
    """A-r2-6: no `running` row is left by a refusal before the spawn."""
    async def fake_launch(self, argv, **kw):
        raise AssertionError("must not start")
    monkeypatch.setattr(Runner, "launch", fake_launch)
    app, c = _client(tmp_path)
    r = c.post("/api/launch", json={"command": "auto", "values": {
        "base_url": "http://127.0.0.1/" + "a" * 3000}})
    assert r.status_code == 409 and "longer than" in r.json()["error"]
    with Store(tmp_path / "start.db", create=False) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM launch").fetchone()[0] == 0


def test_a_stale_side_file_alone_is_named(tmp_path):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("x"))
    (tmp_path / "projects" / "w.fuzzlab-wal").write_bytes(b"x")
    with pytest.raises(ProjectError, match=r"w\.fuzzlab-wal is left over"):
        asyncio.run(mgr.new("w"))


def test_current_is_set_even_when_leaving_raises(tmp_path, monkeypatch):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.temporary())

    def boom(*a, **k):
        raise OSError("injected")
    monkeypatch.setattr(projects, "_remove_project_files", boom)
    assert asyncio.run(mgr.new("next", discard=True)) is True
    assert mgr.store_path() == str(tmp_path / "projects" / "next.fuzzlab")
    # round 3 (C7): the new project's own bookkeeping still ran, and the failure to
    # leave the temporary one is a warning — the action itself succeeded
    assert mgr.pending is None
    assert [r["name"] for r in mgr.recent()] == ["next"]
    assert any(level == "warn" and "leaving it failed: injected" in text
               for level, text in mgr.flash)

    def defect(*a, **k):
        raise sqlite3.ProgrammingError("a defect of ours")
    asyncio.run(mgr.temporary())
    monkeypatch.setattr(projects, "_remove_project_files", defect)
    with pytest.raises(sqlite3.ProgrammingError):             # a defect propagates
        asyncio.run(mgr.new("third", discard=True))


def test_a_project_the_cli_created_meanwhile_is_adopted_not_clobbered(tmp_path, monkeypatch):
    """_ensure_created: the O_EXCL create losing a race to another writer."""
    mgr = ProjectManager(_cfg(tmp_path))
    path = tmp_path / "start.db"
    real = core_project.create

    def racing(p, name=None):
        with Store(p) as store:                     # another process got there first
            store.start_run("cli", "h")
        return real(p, name)
    monkeypatch.setattr(core_project, "create", racing)
    assert mgr._ensure_created() == str(path)
    with Store(path, create=False) as store:
        assert store.conn.execute("SELECT tool FROM run").fetchone()[0] == "cli"
        assert core_project.read_metadata(store)["name"] == "start"


def test_reopening_the_open_temporary_is_a_no_op(tmp_path):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.temporary())
    name = Path(mgr.store_path()).name
    asyncio.run(mgr.open(temporary=name))                  # no "in use" refusal
    assert Path(mgr.store_path()).name == name


def test_a_reused_inode_never_hands_out_another_tools_run(tmp_path):
    """A-r2-4: the cached Repeater run id is re-checked against the store."""
    from fuzzlab.web.proxycontrol import RepeaterController
    from types import SimpleNamespace
    path = tmp_path / "x.fuzzlab"
    core_project.create(path)
    cfg = SimpleNamespace(get=lambda k, d=None: str(path) if k == "store_path" else d)
    ctl = RepeaterController(cfg, sender=lambda *a: b"HTTP/1.1 200 OK\r\n\r\n")
    ctl.create_tab("t", "127.0.0.1", 80, "GET / HTTP/1.1\r\n\r\n")
    ctl._local.store.close()
    ctl._local.store = ctl._local.rep = ctl._local.path = None
    key = ctl._key()
    with Store(path, create=False) as store:              # same file, run id now not ours
        store.conn.execute("UPDATE run SET tool='crawl' WHERE id=?", (ctl._run_ids[key],))
        store.conn.commit()
    ctl.create_tab("t2", "127.0.0.1", 80, "GET / HTTP/1.1\r\n\r\n")
    with Store(path, create=False) as store:
        tools = [r[0] for r in store.conn.execute(
            "SELECT r.tool FROM repeater_tab t JOIN run r ON r.id=t.run_id WHERE t.name='t2'")]
        assert tools == ["repeater"]


# --- start screen and the default store (FR-UI-458, layout pass) ----------------------------

def _default_client(tmp_path, monkeypatch, **over):
    """The built-in default config, run from an empty working directory (layout C2)."""
    monkeypatch.chdir(tmp_path)
    cfg = load_config(overrides={"projects_dir": str(tmp_path / "projects"), **over},
                      environ={})
    app = create_app(cfg)
    return app, web_client(app, follow_redirects=False)


def test_a_default_first_launch_lands_on_the_start_screen(tmp_path, monkeypatch):
    app, c = _default_client(tmp_path, monkeypatch)
    r = c.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/projects"
    page = c.get("/projects").text
    assert 'id="start-temporary"' in page and 'id="start-default"' in page
    assert str(tmp_path / "fuzzlab.db") in page            # the absolute path is shown
    assert c.post("/api/launch", json={"command": "report", "values": {}}).status_code == 409
    r = c.post("/projects/use-default")
    assert r.status_code == 303 and r.headers["location"] == "/"
    st = _state(c)
    assert st["status"] == "open" and st["path"] == str(tmp_path / "fuzzlab.db")
    assert not (tmp_path / "fuzzlab.db").exists()         # created by its first run only


def test_an_existing_default_store_is_opened_as_before(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    core_project.create(tmp_path / "fuzzlab.db")
    app, c = _default_client(tmp_path, monkeypatch)
    assert c.get("/").status_code == 200
    assert _state(c)["path"] == str(tmp_path / "fuzzlab.db")


def test_the_in_process_proxy_adopts_the_default_store_in_a_fresh_directory(tmp_path,
                                                                            monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.chdir(tmp_path)
    cfg = load_config(overrides={"projects_dir": str(tmp_path / "projects")}, environ={})
    proxy = _FakeProxy(str(tmp_path / "fuzzlab.db"))
    app = create_app(cfg, proxy=proxy)
    with TestClient(app, base_url="http://127.0.0.1:8787", headers=SAME_ORIGIN_HEADERS):
        assert proxy.started and (tmp_path / "fuzzlab.db").exists()


def test_opening_an_offer_stays_on_projects_and_success_goes_home(tmp_path):
    """Layout D1/C1: `/` only when the requested project opened and nothing but its ok
    message is queued."""
    app, c = _client(tmp_path, store=None)
    r = c.post("/projects/new", data={"name": "cur"})
    assert r.headers["location"] == "/"
    _older(tmp_path / "projects" / "old.fuzzlab")
    r = c.post("/projects/open", data={"file": "old.fuzzlab"})
    assert r.headers["location"] == "/projects"
    assert 'id="project-migrate-offer"' in c.get("/projects").text
    c.post("/projects/temporary")
    side = core_project.sidecar_dir(Path(_state(c)["path"]))
    (side / "unknown.bin").write_text("x")
    r = c.post("/projects/new", data={"name": "next", "discard": "1"})
    assert r.headers["location"] == "/projects"           # a warning is waiting there
    assert "1 unknown file(s)" in c.get("/projects").text
    # reopening the open project is not an open: no flash, but it stays on /projects
    r = c.post("/projects/open", data={"file": "next.fuzzlab"})
    assert r.headers["location"] == "/projects"


def test_snapshot_keeps_the_project_open_names_safely_and_records_lineage(tmp_path):
    long_name = "n" * 64
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": long_name})
    path = tmp_path / "projects" / f"{long_name}.fuzzlab"
    with Store(path, create=False) as store:
        store.start_run("x", "h")
        src_uuid = core_project.read_metadata(store)["uuid"]
    names = []
    for _ in range(3):                                     # same second: -2, -3
        assert c.post("/projects/snapshot").status_code == 303
        names.append(re.search(r"Snapshot saved as (\S+);", c.get("/projects").text).group(1))
    assert len(set(names)) == 3 and _state(c)["path"] == str(path)
    listed = [f["file"] for f in c.get("/api/projects").json()["files"]]
    for n in names:
        assert n in listed and len(n) <= 64 + len(".fuzzlab")
        with Store(tmp_path / "projects" / n, create=False) as store:
            meta = core_project.read_metadata(store)
            assert meta["copy_kind"] == "snapshot" and meta["origin_uuid"] == src_uuid
            assert meta["uuid"] != src_uuid
            assert store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert stat.S_IMODE(os.stat(tmp_path / "projects" / n).st_mode) == 0o600
    recent = c.get("/api/projects").json()["recent"]
    assert recent and not any(Path(r["path"]).name in names for r in recent)
    assert not any(r["name"] in {Path(n).stem for n in names} for r in recent)


def test_snapshot_stems_fit_the_name_grammar():
    assert projects._grammar_stem("my..db") == "my-db"
    assert projects._grammar_stem("..x") == "x"
    assert projects._grammar_stem("é") == "project"
    for room in (1, 10, 36):
        t = projects._trim_stem("ab. -" * 20, room)
        assert len(t) <= room and projects.NAME_RE.fullmatch(t + "-snapshot")


def test_save_as_of_a_temporary_keeps_its_identity_and_of_a_file_records_origin(tmp_path):
    app, c = _client(tmp_path, store=None)
    c.post("/projects/temporary")
    with Store(Path(_state(c)["path"]), create=False) as store:
        tmp_uuid = core_project.read_metadata(store)["uuid"]
    c.post("/projects/save-as", data={"name": "kept"})
    with Store(tmp_path / "projects" / "kept.fuzzlab", create=False) as store:
        meta = core_project.read_metadata(store)
        assert meta["uuid"] == tmp_uuid and meta["copy_kind"] is None
    c.post("/projects/save-as", data={"name": "copy"})
    with Store(tmp_path / "projects" / "copy.fuzzlab", create=False) as store:
        meta = core_project.read_metadata(store)
        assert meta["origin_uuid"] == tmp_uuid and meta["copy_kind"] == "save-as"


def test_remove_from_list_matches_index_and_path_and_leaves_the_file(tmp_path):
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "a"})
    c.post("/projects/new", data={"name": "b"})
    recent = c.get("/api/projects").json()["recent"]
    a = [r for r in recent if r["name"] == "a"][0]
    c.post("/projects/forget", data={"recent": str(a["id"]), "path": "/elsewhere"})
    assert "the recent list changed" in _flash(c)
    c.post("/projects/forget", data={"recent": str(a["id"]), "path": a["path"]})
    assert [r["name"] for r in c.get("/api/projects").json()["recent"]] == ["b"]
    assert (tmp_path / "projects" / "a.fuzzlab").exists()


def test_a_leftover_discard_needs_its_confirmation(tmp_path):
    a = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(a.temporary())
    name = Path(a.store_path()).name
    projects._release_owner(a.current.owner_fd)
    a.current.owner_fd = None
    app, c = _client(tmp_path, store=None)
    c.post("/projects/discard-temporary", data={"temporary": name})
    assert "Tick" in _flash(c) and (tmp_path / "projects" / ".temporary" / name).exists()
    c.post("/projects/discard-temporary", data={"temporary": name, "discard": "1"})
    assert not (tmp_path / "projects" / ".temporary" / name).exists()


def test_the_last_written_time_ignores_readers(tmp_path):
    """Layout D2: readers create an empty -wal and a -shm; neither moves the time."""
    path = tmp_path / "p.fuzzlab"
    core_project.create(path)
    with Store(path, create=False) as store:
        store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    old = 1_700_000_000
    os.utime(path, (old, old))
    before = core_project.file_facts(path)
    with Store(path, create=False):                       # a reader
        core_project.summary(path)
        core_project.inspect(path)
        assert core_project.file_facts(path)["written_at"] == before["written_at"]


def test_summary_refuses_a_view_named_run_and_is_bounded(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "v.fuzzlab"
    Store(path).close()
    conn = sqlite3.connect(path)
    conn.execute("DROP TABLE run")
    conn.execute("CREATE VIEW run AS WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL "
                 "SELECT x+1 FROM c) SELECT x AS id FROM c")
    conn.commit()
    conn.close()
    assert core_project.summary(path) == {"readable": False}
    cheap = tmp_path / "c.fuzzlab"                         # refused by the allowlist,
    Store(cheap).close()                                   # not only by the budget
    conn = sqlite3.connect(cheap)
    conn.execute("DROP TABLE run")
    conn.execute("CREATE VIEW run AS SELECT 1 AS id")
    conn.commit()
    conn.close()
    assert core_project.summary(cheap) == {"readable": False}
    good = tmp_path / "g.fuzzlab"
    core_project.create(good)
    monkeypatch.setattr(core_project, "SUMMARY_STEP_BUDGET", 0)
    core_project._SUMMARY_CACHE.clear()
    assert core_project.summary(good) == {"readable": False}     # the budget aborts
    monkeypatch.undo()
    core_project._SUMMARY_CACHE.clear()
    assert core_project.summary(good)["readable"] is True


def test_history_labels_an_interrupted_job(tmp_path):
    with Store(tmp_path / "s.db") as store:
        core_project.ensure_metadata(store, "s")
        core_project.insert_launch(store, "auto", [("", "fuzzlab")], None)
        core_project.ensure_metadata(store, "s")           # the UI ended first
        rows = core_project.run_history(store)
        assert rows[0]["label"] == "interrupted" and rows[0]["status"] == "unknown"


# --- code review round 3 --------------------------------------------------------------

def test_an_older_leftover_temporary_stays_temporary_when_migrated(tmp_path):
    """C2: the migration offer forgot it was a temporary — it opened as a plain file
    with no owner lock and joined the recent list."""
    a = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(a.temporary())
    path = Path(a.store_path())
    projects._release_owner(a.current.owner_fd)
    a.current.owner_fd = None
    with Store(path, create=False) as store:              # make it an older store
        undo_after(store.conn, 21)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 22")
        store.conn.commit()
    b = ProjectManager(_cfg(tmp_path, store=None))
    assert asyncio.run(b.open(temporary=path.name)) is False
    assert b.pending.kind == "older" and b.pending.project_kind == "temporary"
    asyncio.run(b.migrate_pending())
    assert b.current.kind == "temporary" and b.current.owner_fd is not None
    assert b.current.inode == (os.stat(path).st_dev, os.stat(path).st_ino)
    assert b.recent() == []                                # never in the recent list
    c = ProjectManager(_cfg(tmp_path, store=None))         # a second UI cannot discard it
    with pytest.raises(ProjectError, match="in use"):
        asyncio.run(c.discard_leftover(path.name, confirm=True))
    with pytest.raises(projects.NeedsDiscard):
        asyncio.run(b.close())


def test_dismiss_takes_the_lock_and_a_vanished_offer_is_a_refusal(tmp_path):
    """C12: Not now raced a migration (an AssertionError, a 500)."""
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    with pytest.raises(ProjectError, match="no migration is waiting"):
        mgr._migrate_pending(False)
    assert asyncio.iscoroutinefunction(ProjectManager.dismiss_pending)


def test_reopening_the_open_project_from_recent_is_a_no_op_even_while_busy(tmp_path):
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("a"))
    entry = mgr.recent()[0]
    mgr.extra_busy["job"] = "a job"
    assert asyncio.run(mgr.open(recent_id=entry["id"], recent_path=entry["path"])) is False
    mgr.extra_busy.clear()


def test_the_default_offer_says_whether_the_default_store_exists(tmp_path, monkeypatch):
    app, c = _default_client(tmp_path, monkeypatch)
    assert "created by its first run" in c.get("/projects").text
    c.post("/projects/use-default")
    with Store(tmp_path / "fuzzlab.db") as store:          # its first run
        store.start_run("x", "h")
    c.post("/projects/close")
    page = c.get("/projects").text
    assert 'id="start-default"' in page and "created by its first run" not in page


def test_the_open_list_counts_the_wal(tmp_path):
    """C9: the Open list's size and time came from the main file only."""
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("a"))
    path = tmp_path / "projects" / "a.fuzzlab"
    old = 1_700_000_000
    os.utime(path, (old, old))
    store = Store(path, create=False)
    try:
        store.conn.execute("PRAGMA wal_autocheckpoint=0")
        store.start_run("x", "h")                          # lands in the -wal
        assert os.stat(str(path) + "-wal").st_size > 0
        row = [f for f in mgr.list_files() if f["file"] == "a.fuzzlab"][0]
        facts = core_project.file_facts(path)
        assert row["size"] == facts["size"] > os.stat(path).st_size
        assert row["modified"] == facts["written_at"] and not row["modified"].startswith("2023")
    finally:
        store.close()


def test_a_database_error_while_recording_a_job_is_a_409_not_a_500(tmp_path, monkeypatch):
    """C6: the launch workers were not wrapped by `_refusal`."""
    async def fake_launch(self, argv, **kw):
        raise AssertionError("must not start")
    monkeypatch.setattr(Runner, "launch", fake_launch)

    def locked(*a, **k):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(core_project, "insert_launch", locked)
    from fastapi.testclient import TestClient
    app = create_app(_cfg(tmp_path))
    c = TestClient(app, base_url="http://127.0.0.1:8787", headers=SAME_ORIGIN_HEADERS,
                   raise_server_exceptions=False)
    r = c.post("/api/launch", json={"command": "report", "values": {}})
    assert r.status_code == 409 and "recording the job failed" in r.json()["error"]


def test_refusal_converts_file_trouble_and_propagates_defects():
    """PA-0106(2): one converted error, one propagated (C6)."""
    @projects._refusal("x")
    def raises(exc):
        raise exc
    for exc in (OSError("disk"), sqlite3.OperationalError("locked"),
                sqlite3.DatabaseError("file is not a database"), sqlite3.DataError("big")):
        with pytest.raises(ProjectError, match="x failed"):
            raises(exc)
    for exc in (sqlite3.ProgrammingError("misuse"), sqlite3.IntegrityError("ours"),
                sqlite3.InterfaceError("api"), ValueError("other")):
        with pytest.raises(type(exc)):
            raises(exc)


def test_a_malformed_project_identity_is_shown_as_unknown(tmp_path):
    app, c = _client(tmp_path, store=None)
    c.post("/projects/new", data={"name": "a"})
    with Store(tmp_path / "projects" / "a.fuzzlab", create=False) as store:
        store.conn.execute("UPDATE project SET uuid='not-hex', copy_kind='Snapshot', "
                           "name=X'41', created_at=X'42'")
        store.conn.commit()
    page = c.get("/project").text
    assert 'id="project-identity-malformed"' in page and "None" not in page


def test_a_case_variant_trigger_never_fires_through_the_ui(tmp_path):
    """C10 / PA-0451(2): the planted row really fires on a plain open, and opening the
    file through the UI refuses it before anything is written."""
    import shutil
    pdir = tmp_path / "projects"
    mgr = ProjectManager(_cfg(tmp_path, store=None))
    asyncio.run(mgr.new("cur"))
    evil = pdir / "evil.fuzzlab"
    core_project.create(evil)
    conn = sqlite3.connect(evil)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("CREATE TABLE marker (x)")
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute("INSERT INTO sqlite_master VALUES ('TRIGGER','evil','project',0,"
                 "'CREATE TRIGGER evil AFTER UPDATE ON project BEGIN "
                 "INSERT INTO marker VALUES (1); END')")
    conn.commit()
    conn.close()
    os.chmod(evil, 0o600)
    probe = tmp_path / "probe.db"                        # non-vacuity, on a copy
    shutil.copy(evil, probe)
    conn = sqlite3.connect(probe)
    conn.execute("UPDATE project SET opened_at='t'")
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM marker").fetchone()[0] == 1
    conn.close()
    with pytest.raises(ProjectError, match=r"TRIGGER evil.*refused as untrusted"):
        asyncio.run(mgr.open(file="evil.fuzzlab"))
    assert mgr.store_path() == str(pdir / "cur.fuzzlab")
    conn = sqlite3.connect(evil)
    assert conn.execute("SELECT COUNT(*) FROM marker").fetchone()[0] == 0
    conn.close()


def test_the_default_store_guard_sees_changes_to_an_existing_store(tmp_path):
    """Code review round 3 (S5/C11): the guard was off when ./fuzzlab.db pre-existed."""
    from tests.conftest import _default_store_state
    path = str(tmp_path / "fuzzlab.db")
    empty = _default_store_state(path)
    assert set(empty.values()) == {None} and len(empty) == 5
    Path(path).write_bytes(b"x")
    before = _default_store_state(path)
    os.utime(path, ns=(1, 1))
    assert _default_store_state(path) != before
    (tmp_path / "fuzzlab.db.d").mkdir()
    assert _default_store_state(path)[path + ".d"] is not None
