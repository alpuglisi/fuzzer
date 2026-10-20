"""The web process never drops SQLite's locks on a store (BUG-0535, PA-0535, FR-CORE-508).

On POSIX, closing **any** file descriptor of a file releases every ``fcntl`` lock the
process holds on that file. SQLite's WAL protection is such a lock: while a connection of
the web process holds its shared lock, no other process's close can fold the WAL and
delete ``-wal``/``-shm``. A plain ``open()``/``close()`` of the store's main file in the
web process (the Projects listing's magic-byte read, ``core.project.summary``/``inspect``)
silently dropped that lock for every connection the process held, so the next close by
another process deleted the side files under them: wrong reads, lost commits and a
corrupt project file, measured on 7ebf48a (DRAFT-AU-SITETREE §1.7).

Every writer here runs in another process (`tests/_xproc.py`): the hazard is between
processes. The guard at the end keeps every raw open of a file out of the modules the web
process uses to handle stores, except reviewed sites that never touch a store's files.
"""

from __future__ import annotations

import ast
import asyncio
import os
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core import project as core_project  # noqa: E402
from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web import sitetree  # noqa: E402
from fuzzlab.web.projects import ProjectManager, open_reader  # noqa: E402
from tests._xproc import Writer, one_commit  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SHORT = "INSERT INTO run (tool, config_hash) VALUES ('short', 'h')"


def _project(tmp_path):
    """A project file in a private projects directory, and the manager that lists it."""
    pdir = tmp_path / "projects"
    pdir.mkdir(mode=0o700)
    path = pdir / "p.fuzzlab"
    core_project.create(path, "p")
    cfg = load_config(overrides={"store_path": "", "projects_dir": str(pdir),
                                 "authorized": True}, environ={})
    return path, ProjectManager(cfg)


def _listing(mgr):
    """The Projects page's listing, reading the file (not a cached summary)."""
    core_project._SUMMARY_CACHE.clear()
    rows = mgr.list_files()
    # the premise (PA-0311(2)): the listing read this very file
    assert len(rows) == 1 and rows[0]["summary"]["readable"], rows
    return rows


def _side(path) -> set[str]:
    return {s for s in ("-wal", "-shm") if os.path.exists(str(path) + s)}


def _elsewhere(path, *queries):
    """What another process reads now: integrity, then each query's first value."""
    with Writer(path) as w:
        w("open_plain")
        return tuple([w("count", "PRAGMA integrity_check")]
                     + [w("count", q) for q in queries])


def _flow(i):
    from fuzzlab.proxy.history import FlowRecord
    return FlowRecord(method="GET", url=f"http://127.0.0.1:9/f{i}", host="127.0.0.1",
                      status=200, raw_request=b"GET /f HTTP/1.1\r\nHost: x\r\n\r\n",
                      raw_response=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


# --- BUG-0535 on today's code: the connections the web process already holds -------------

def test_a_projects_listing_never_drops_the_in_process_proxys_store_locks(tmp_path):
    """`fuzzlab web --with-proxy` holds a Store for the proxy's life. One Projects view and
    one short writer in another process deleted -wal/-shm under it on 7ebf48a; the file was
    corrupt afterwards (`vtable constructor failed: flow_fts`)."""
    from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController
    path, mgr = _project(tmp_path)
    ctl = ProxyController(ProxyConfig(store_path=str(path))).build()
    try:
        ctl._history.record(_flow(0))
        _listing(mgr)
        one_commit(path, SHORT)                      # a CLI tool: open, commit, close
        assert _side(path) == {"-wal", "-shm"}, \
            "another process's close folded and deleted the WAL under the proxy's Store"
        for i in range(1, 11):
            ctl._history.record(_flow(i))
    finally:
        asyncio.run(ctl.stop())
    assert _elsewhere(path, "SELECT count(*) FROM flow",
                      "SELECT count(*) FROM run WHERE tool='short'") == ("ok", 11, 1)


def test_a_projects_listing_never_drops_a_request_readers_locks(tmp_path):
    """A site-map request in flight on another thread spans a Projects listing. On 7ebf48a
    every per-request read during a scan in another process was wrong (100 of 100), the
    held reader read "malformed", and 4 of 5 UI commits were lost."""
    path, mgr = _project(tmp_path)
    reader = open_reader(str(path))                  # the request in flight
    try:
        reader.conn.execute("SELECT count(*) FROM run").fetchone()
        _listing(mgr)
        one_commit(path, SHORT)
        assert _side(path) == {"-wal", "-shm"}, \
            "another process's close folded and deleted the WAL under a request's reader"
        with Writer(path) as scan:                   # a scan in another process
            scan("open")
            for i in range(1, 21):
                scan("ins", 1)
                fresh = open_reader(str(path))       # a per-request reader
                try:
                    assert fresh.conn.execute(
                        "SELECT count(*) FROM endpoint").fetchone()[0] == i
                finally:
                    fresh.close()
            with Store(path, create=False) as ui:    # a UI write (Repeater, saved view)
                ui.start_run("ui", "h")
            scan("close")
        assert reader.conn.execute("SELECT count(*) FROM endpoint").fetchone()[0] == 20
    finally:
        reader.close()
    assert _elsewhere(path, "SELECT count(*) FROM endpoint",
                      "SELECT count(*) FROM run WHERE tool='ui'") == ("ok", 20, 1)


def test_opening_a_project_never_drops_a_held_connections_locks(tmp_path):
    """`core.project.inspect` (opening, re-checking or migrating a project) read the magic
    bytes with open() too."""
    path, _mgr = _project(tmp_path)
    held = Store(path, create=False)                 # e.g. the in-process proxy's Store
    try:
        held.start_run("held", "h")
        assert core_project.inspect(path).state == "ok"
        one_commit(path, SHORT)
        assert _side(path) == {"-wal", "-shm"}, \
            "another process's close folded and deleted the WAL under a held Store"
        held.start_run("held", "h")
    finally:
        held.close()
    assert _elsewhere(path, "SELECT count(*) FROM run WHERE tool='held'") == ("ok", 2)


def test_a_projects_listing_never_drops_the_store_watchs_locks(tmp_path):
    """The store version's held watch (CC-UI-0068) is the connection the reviewers saw
    break: after a listing and a short writer it missed every later commit (200 of 200,
    300 of 300). It must keep seeing each commit of a scan in another process."""
    path, mgr = _project(tmp_path)
    sitetree.store_version(str(path))
    _listing(mgr)
    one_commit(path, SHORT)
    with Writer(path) as scan:
        scan("open")
        prev = sitetree.store_version(str(path))
        for _ in range(50):
            scan("ins", 1)
            cur = sitetree.store_version(str(path))
            assert cur is not None and cur != prev
            prev = cur
        scan("close")


# --- the guard (PA-0535): no raw open in the modules that handle stores in the web ------

#: Calls that open a file outside SQLite. Any one of them, on a store's main file, -wal or
#: -shm, drops the process's locks when it closes.
_READS = {"read_bytes", "read_text", "write_bytes", "write_text"}
_SHUTIL = {"copy", "copy2", "copyfile", "move"}
#: What makes a module one that handles stores: it opens SQLite.
_SQLITE_OPENERS = {"open_store", "Store", "open_read_only"}


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _module_path(root: Path, name: str) -> Path | None:
    p = root.joinpath(*name.split("."))
    if p.with_suffix(".py").is_file():
        return p.with_suffix(".py")
    if (p / "__init__.py").is_file():
        return p / "__init__.py"
    return None


def _imports(root: Path, path: Path) -> set[str]:
    """Every fuzzlab module ``path`` imports, function-level (lazy) imports included."""
    me = _module_name(root, path)
    pkg = me if path.name == "__init__.py" else me.rpartition(".")[0]
    out: set[str] = set()
    for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            out |= {a.name for a in n.names if a.name.startswith("fuzzlab")}
        elif isinstance(n, ast.ImportFrom):
            base = n.module or ""
            if n.level:
                up = pkg.split(".")[:len(pkg.split(".")) - (n.level - 1)]
                base = ".".join(up + ([base] if base else []))
            if base.startswith("fuzzlab"):
                out |= {base} | {f"{base}.{a.name}" for a in n.names}
    return out


def _opens_sqlite(tree) -> bool:
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr == "connect" \
                and isinstance(f.value, ast.Name) and f.value.id == "sqlite3":
            return True
        if isinstance(f, ast.Name) and f.id in _SQLITE_OPENERS:
            return True
        if isinstance(f, ast.Attribute) and f.attr in _SQLITE_OPENERS:
            return True
    return False


def web_scope(root: Path) -> list[Path]:
    """The modules the web process uses to handle stores: every module of ``fuzzlab/web``,
    and every module the web package imports (transitively, lazy imports included) that
    opens SQLite. Computed, never listed."""
    roots = [_module_name(root, p) for p in sorted((root / "fuzzlab" / "web").rglob("*.py"))]
    seen: set[str] = set()
    todo = list(roots)
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        p = _module_path(root, name)
        if p is None:
            continue
        seen.add(name)
        todo += sorted(_imports(root, p))
        parts = name.split(".")
        todo += [".".join(parts[:i]) for i in range(1, len(parts))]
    out = []
    for name in sorted(seen):
        p = _module_path(root, name)
        if name == "fuzzlab.web" or name.startswith("fuzzlab.web.") \
                or _opens_sqlite(ast.parse(p.read_text(encoding="utf-8"))):
            out.append(p)
    return out


def raw_opens(src: str) -> Counter:
    """``{(function, shape): count}`` of every call that opens a file outside SQLite."""
    found: Counter = Counter()

    def visit(node, where):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(ch, f"{where}.{ch.name}" if where else ch.name)
                continue
            if isinstance(ch, ast.Call):
                f, shape = ch.func, None
                if isinstance(f, ast.Name) and f.id == "open":
                    shape = "open()"
                elif isinstance(f, ast.Attribute):
                    owner = f.value.id if isinstance(f.value, ast.Name) else None
                    if owner in ("os", "io") and f.attr in ("open", "fdopen"):
                        shape = f"{owner}.{f.attr}()"
                    elif f.attr == "open":
                        shape = ".open()"
                    elif f.attr in _READS:
                        shape = f".{f.attr}()"
                    elif owner == "shutil" and f.attr in _SHUTIL:
                        shape = f"shutil.{f.attr}()"
                if shape:
                    found[(where or "<module>", shape)] += 1
            visit(ch, where)

    visit(ast.parse(src), "")
    return found


def scan(root: Path = REPO) -> Counter:
    found: Counter = Counter()
    for path in web_scope(root):
        rel = path.relative_to(root).as_posix()
        for (func, shape), n in raw_opens(path.read_text(encoding="utf-8")).items():
            found[(rel, func, shape)] += n
    return found


_NEW = ("a new inode this call created with O_EXCL; no SQLite connection of any process "
        "can hold it when it is opened or closed")
_NOT_A_STORE = "never a store's main file, -wal or -shm: "
#: Every raw open in the scope, with its count and why it never touches a store's files.
#: The scan must equal this exactly: a new site and a stale entry both fail.
ALLOWED: dict[tuple[str, str, str], tuple[int, str]] = {
    ("fuzzlab/core/project.py", "create", "os.open()"): (1, _NEW),
    ("fuzzlab/core/project.py", "copy_to", "os.open()"): (
        2, _NEW + "; the second open (fsync) follows the close of every connection of the "
           "copy, which no other process knows"),
    ("fuzzlab/greybox/greybox_cli.py", "_cookie_for", ".open()"): (
        1, _NOT_A_STORE + "the operator's cookie file (the CLI's process)"),
    ("fuzzlab/harness/auto_cli.py", "_account_values", ".open()"): (
        1, _NOT_A_STORE + "the account values file (the CLI's process)"),
    ("fuzzlab/harness/auto_cli.py", "_precheck_peer", ".open()"): (
        1, _NOT_A_STORE + "the peer account file (the CLI's process)"),
    ("fuzzlab/tools/authhttp.py", "_build_parts", ".open()"): (
        1, _NOT_A_STORE + "a request body part the operator named"),
    ("fuzzlab/tools/blind_sqli_fuzzer.py", "save_dataset", "open()"): (
        1, _NOT_A_STORE + "the dataset CSV the tool writes"),
    ("fuzzlab/tools/observe.py", "_guard_hosts", ".read_text()"): (
        1, _NOT_A_STORE + "a disco run's JSON file"),
    ("fuzzlab/tools/observe.py", "observe_disco", ".read_text()"): (
        1, _NOT_A_STORE + "a disco run's JSON file"),
    ("fuzzlab/tools/store_adapter.py", "_disco_actions", "open()"): (
        1, _NOT_A_STORE + "a disco run's actions.jsonl"),
    ("fuzzlab/tools/store_adapter.py", "_disco_code_segments", ".read_text()"): (
        1, _NOT_A_STORE + "a disco run's code segments file"),
    ("fuzzlab/tools/store_adapter.py", "import_fuzz_csv", "open()"): (
        1, _NOT_A_STORE + "the fuzz CSV"),
    ("fuzzlab/web/labcontrol.py", "_load_compose", ".read_text()"): (
        1, _NOT_A_STORE + "the lab's compose YAML"),
    ("fuzzlab/web/projectroutes.py", "register.project_open.go", ".open()"): (
        1, "ProjectManager.open, a method, not a file"),
    ("fuzzlab/web/projects.py", "ProjectManager._copy_sidecars", ".read_bytes()"): (
        1, _NOT_A_STORE + "a non-SQLite sidecar (the fuzz CSV); the `.db` sidecars go "
           "through core.project.copy_to, SQLite's backup API"),
    ("fuzzlab/web/projects.py", "_acquire_owner", "os.open()"): (
        1, _NOT_A_STORE + "the project directory's .owner.lock (flock)"),
    ("fuzzlab/web/projects.py", "_parse_recent", "os.open()"): (
        1, _NOT_A_STORE + "the recent list (recent.json)"),
    ("fuzzlab/web/projects.py", "_remove_own_backups", "os.open()"): (
        1, _NOT_A_STORE + "a directory descriptor (O_DIRECTORY)"),
    ("fuzzlab/web/projects.py", "_remove_project_files", "os.open()"): (
        2, _NOT_A_STORE + "directory descriptors (O_DIRECTORY)"),
}


def _mismatch(found: Counter, allowed=ALLOWED) -> list[str]:
    out = [f"{k}: {n} raw open(s), not allowed" for k, n in sorted(found.items())
           if allowed.get(k, (0, ""))[0] != n]
    out += [f"{k}: stale allowance" for k in sorted(allowed) if k not in found]
    return out


def test_no_web_process_module_opens_a_store_file_except_through_sqlite():
    """PA-0535: in the modules the web process uses to handle stores, a file is opened
    outside SQLite only at a reviewed site that never touches a store's files. Whether a
    file is SQLite is asked of SQLite (`core.store.open_read_only`, FR-CORE-508)."""
    assert _mismatch(scan()) == []


def _tree(tmp_path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_the_store_file_guard_catches_synthetic_offenders(tmp_path):
    """PA-0034(2): each raw-open shape is found; a module reached only by a lazy import is
    in scope when it opens SQLite and out of scope when it does not; an allowed site
    passes; a new site in an allowed function and a stale allowance both fail."""
    root = _tree(tmp_path, {
        "fuzzlab/__init__.py": "",
        "fuzzlab/web/__init__.py": "",
        "fuzzlab/web/page.py": (
            "def route(p):\n"
            "    from fuzzlab.core import helper\n"
            "    from fuzzlab.core.other import x\n"
            "    return helper.check(p)\n"),
        "fuzzlab/web/direct.py": (
            "import io, os, shutil\n"
            "from pathlib import Path\n"
            "def magic(p):\n"
            "    with open(p, 'rb') as fh:\n"
            "        return fh.read(16)\n"
            "def many(p):\n"
            "    os.close(os.open(p, os.O_RDONLY))\n"
            "    io.open(p).close()\n"
            "    Path(p).open().close()\n"
            "    Path(p).read_bytes(); Path(p).read_text()\n"
            "    Path(p).write_bytes(b''); Path(p).write_text('')\n"
            "    shutil.copyfile(p, p + '.bak')\n"
            "    os.fdopen(3)\n"),
        "fuzzlab/core/__init__.py": "",
        "fuzzlab/core/helper.py": (
            "import sqlite3\n"
            "def check(p):\n"
            "    sqlite3.connect(p).close()\n"
            "    return open(p, 'rb').read(16)\n"),
        "fuzzlab/core/other.py": (
            "x = 1\n"
            "def unrelated(p):\n"
            "    return open(p).read()\n"),
    })
    found = scan(root)
    assert found == Counter({
        ("fuzzlab/web/direct.py", "magic", "open()"): 1,
        ("fuzzlab/web/direct.py", "many", "os.open()"): 1,
        ("fuzzlab/web/direct.py", "many", "io.open()"): 1,
        ("fuzzlab/web/direct.py", "many", ".open()"): 1,
        ("fuzzlab/web/direct.py", "many", ".read_bytes()"): 1,
        ("fuzzlab/web/direct.py", "many", ".read_text()"): 1,
        ("fuzzlab/web/direct.py", "many", ".write_bytes()"): 1,
        ("fuzzlab/web/direct.py", "many", ".write_text()"): 1,
        ("fuzzlab/web/direct.py", "many", "shutil.copyfile()"): 1,
        ("fuzzlab/web/direct.py", "many", "os.fdopen()"): 1,
        ("fuzzlab/core/helper.py", "check", "open()"): 1,     # lazy import, opens SQLite
    })                                                         # core/other.py: no SQLite
    allowed = {k: (n, "synthetic") for k, n in found.items()}
    assert _mismatch(found, allowed) == []
    grown = found + Counter({("fuzzlab/core/helper.py", "check", "open()"): 1})
    assert _mismatch(grown, allowed) == [
        "('fuzzlab/core/helper.py', 'check', 'open()'): 2 raw open(s), not allowed"]
    stale = {**allowed, ("fuzzlab/web/gone.py", "f", "open()"): (1, "synthetic")}
    assert _mismatch(found, stale) == ["('fuzzlab/web/gone.py', 'f', 'open()'): stale allowance"]
    assert _mismatch(found, {}) != []
