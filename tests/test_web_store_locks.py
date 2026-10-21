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
    300 of 300). Its locks hold across the listing (the side files are still there after
    another process's close), and the same watch -- never a reopened one, whose new epoch
    would change the version by itself -- sees each commit of a scan in another process.
    (Without the first two asserts this passed on the pre-fix `project.py`: the side
    files went, the identity re-check reopened the watch, and a new epoch made every
    version differ anyway; the confirming review of `eb95cd4`.)"""
    path, mgr = _project(tmp_path)
    assert sitetree.store_version(str(path)) is not None
    epoch = sitetree._watch.epoch
    _listing(mgr)
    one_commit(path, SHORT)
    assert _side(path) == {"-wal", "-shm"}, \
        "another process's close folded and deleted the WAL under the store's watch"
    with Writer(path) as scan:
        scan("open")
        prev = sitetree.store_version(str(path))
        assert prev is not None, "the watch lost the store after the listing"
        for _ in range(50):
            scan("ins", 1)
            cur = sitetree.store_version(str(path))
            assert cur is not None and cur != prev
            assert sitetree._watch.epoch == epoch, "the watch was reopened"
            prev = cur
        scan("close")


# --- the guard (PA-0535): no raw open of a file in the web process's code ----------------
# Two layers. (1) A static guard over the web process's code: every module the web
# package imports, transitively, lazy imports and literal `importlib.import_module`
# included -- a helper a route hands a path to opens it in the web process whether or not
# it opens SQLite itself (the confirming review found 21 such modules with 41 sites
# outside revision 2's SQLite-only scope). Every call that opens a file by name outside
# SQLite is a reviewed allowance with its count and its reason. (2) A run-time audit hook
# (`tests/_store_audit.py`, armed for every web test by `tests/conftest.py`) fails a test
# during which production code opened a store's main file, -wal or -shm outside SQLite,
# whatever the call.
#
# What neither sees: code that is not in the import graph (an entry-point plugin
# `PluginManager.from_entry_points` loads into the web process, a module imported by a
# computed name) is outside (1) and, unless a web test runs it, (2); an open by C code
# that raises no audit event; an open in another process. The cross-process tests above
# are the proof of the behaviour; these keep the code from regressing.

#: Calls that open a file by name outside SQLite. Any one of them, on a store's main
#: file, -wal or -shm, drops the process's SQLite locks on that file when it closes.
_READS = {"read_bytes", "read_text", "write_bytes", "write_text"}
_SHUTIL = {"copy", "copy2", "copyfile", "copyfileobj", "move", "copytree", "make_archive",
           "unpack_archive"}
_FILECMP = {"cmp", "cmpfiles", "dircmp"}
_TEMPFILE = {"mkstemp", "NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile"}
#: Starlette serves a file by its path (`FileResponse`) or from a directory (`StaticFiles`).
_SERVERS = {"FileResponse", "StaticFiles"}
#: An archive opened by name, and the call that reads another file into it.
_ARCHIVES = {"ZipFile": "write", "TarFile": "add"}


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
    """Every fuzzlab module ``path`` imports: module- and function-level ``import``s and
    ``importlib.import_module("fuzzlab....")`` with a literal name."""
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
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "import_module" and n.args \
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) \
                and n.args[0].value.startswith("fuzzlab"):
            out.add(n.args[0].value)
    return out


def web_scope(root: Path) -> list[Path]:
    """The web process's code: every module of ``fuzzlab/web`` and every module it imports,
    transitively (with each module's parent packages). Computed, never listed."""
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
    return [_module_path(root, name) for name in sorted(seen)]


def _callee(f) -> tuple[str | None, str | None]:
    """``(owner, name)`` of a call: ``(None, "open")`` for ``open(...)``, ``("os", "open")``
    for ``os.open(...)``, ``("", "open")`` for ``x.y.open(...)``."""
    if isinstance(f, ast.Name):
        return None, f.id
    if isinstance(f, ast.Attribute):
        return (f.value.id if isinstance(f.value, ast.Name) else ""), f.attr
    return None, None


def _archive_bindings(scope) -> dict[str, str]:
    """Names a scope binds to an archive opened by name (``with ZipFile(p) as z``,
    ``t = tarfile.open(p)``): their ``.write``/``.add`` open another file."""
    out = {}
    for n in ast.walk(scope):
        pairs = []
        if isinstance(n, ast.withitem) and isinstance(n.optional_vars, ast.Name):
            pairs.append((n.optional_vars.id, n.context_expr))
        elif isinstance(n, ast.Assign):
            pairs += [(t.id, n.value) for t in n.targets if isinstance(t, ast.Name)]
        for name, value in pairs:
            if isinstance(value, ast.Call):
                owner, attr = _callee(value.func)
                if attr in _ARCHIVES:
                    out[name] = attr
                elif owner == "tarfile" and attr == "open":
                    out[name] = "TarFile"
    return out


#: The library modules whose openers the guard knows: an alias of one, or a name imported
#: from one, is resolved to it (``import shutil as sh``, ``from os import open as o``).
_OPENER_MODULES = {"os", "io", "shutil", "filecmp", "tempfile", "zipfile", "tarfile"}


def _aliases(tree) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """``(modules, names)`` a module binds to an opener module: ``import shutil as sh``
    gives ``{"sh": "shutil"}``; ``from shutil import copyfile`` gives ``{"copyfile":
    ("shutil", "copyfile")}``. Anywhere in the module (a lazy import included)."""
    mods: dict[str, str] = {}
    names: dict[str, tuple[str, str]] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods.update({a.asname: a.name for a in n.names
                         if a.asname and a.name in _OPENER_MODULES})
        elif isinstance(n, ast.ImportFrom) and not n.level and n.module in _OPENER_MODULES:
            names.update({a.asname or a.name: (n.module, a.name) for a in n.names})
    return mods, names


def _shape(call: ast.Call, bound: dict[str, str], aliases=({}, {})) -> str | None:
    owner, attr = _callee(call.func)
    if attr is None:
        return None
    mods, names = aliases
    if owner is None and attr in names:                 # from os import open as o
        owner, attr = names[attr]
    owner = mods.get(owner, owner)                      # import shutil as sh
    if owner is None:                                   # a bare name
        if attr == "open":
            return "open()"
        return f"{attr}()" if attr in _SERVERS or attr in _ARCHIVES else None
    if owner in ("os", "io") and attr in ("open", "fdopen", "FileIO"):
        return f"{owner}.{attr}()"
    if owner == "shutil" and attr in _SHUTIL:
        return f"shutil.{attr}()"
    if owner == "filecmp" and attr in _FILECMP:
        return f"filecmp.{attr}()"
    if owner == "tempfile" and attr in _TEMPFILE:
        return f"tempfile.{attr}()"
    if attr in _SERVERS or attr in _ARCHIVES:
        return f"{attr}()"
    if owner in bound and attr == _ARCHIVES[bound[owner]]:
        return f"{bound[owner]}.{attr}()"
    if attr == "open":
        return ".open()"
    return f".{attr}()" if attr in _READS else None


def raw_opens(src: str) -> Counter:
    """``{(function, shape): count}`` of every call that opens a file outside SQLite."""
    found: Counter = Counter()

    def visit(node, where, bound):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(ch, f"{where}.{ch.name}" if where else ch.name,
                      {**bound, **_archive_bindings(ch)})
                continue
            if isinstance(ch, ast.ClassDef):
                visit(ch, f"{where}.{ch.name}" if where else ch.name, bound)
                continue
            if isinstance(ch, ast.Call):
                shape = _shape(ch, bound, aliases)
                if shape:
                    found[(where or "<module>", shape)] += 1
            visit(ch, where, bound)

    tree = ast.parse(src)
    aliases = _aliases(tree)
    visit(tree, "", _archive_bindings(tree))
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
_CLI = " (a CLI's own process; the web process imports it for its parser)"
_LAB = " (lab generation; the web process imports it for the lab page's command specs)"
#: Every raw open in the scope, with its count and why it never touches a store's files.
#: The scan must equal this exactly: a new site and a stale entry both fail.
ALLOWED: dict[tuple[str, str, str], tuple[int, str]] = {
    ("fuzzlab/audit/rules.py", "load_rules", ".read_text()"): (
        2, _NOT_A_STORE + "the packaged default rules, or a rules JSON the operator names"),
    ("fuzzlab/core/config.py", "load_config", ".read_text()"): (
        1, _NOT_A_STORE + "a JSON config file"),
    ("fuzzlab/core/credentials.py", "_CryptographyFileBackend._load", ".read_bytes()"): (
        1, _NOT_A_STORE + "the encrypted credential file (D12)"),
    ("fuzzlab/core/project.py", "create", "os.open()"): (1, _NEW),
    ("fuzzlab/core/project.py", "copy_to", "os.open()"): (
        2, _NEW + "; the second open (fsync) follows the close of every connection of the "
           "copy, which no other process knows"),
    ("fuzzlab/core/secretfile.py", "_fsync_dir", "os.open()"): (
        1, _NOT_A_STORE + "a directory descriptor (O_DIRECTORY)"),
    ("fuzzlab/core/secretfile.py", "create_secret", "os.open()"): (
        1, _NOT_A_STORE + "a secret file (O_EXCL; the recent list, a key)"),
    ("fuzzlab/core/secretfile.py", "locked", "os.open()"): (
        1, _NOT_A_STORE + "a sibling '<file>.lock' (flock), never the file itself"),
    ("fuzzlab/core/secretfile.py", "write_secret", "os.open()"): (
        1, _NOT_A_STORE + "a secret file's temporary sibling (the recent list, a key; "
           "web/projects.py:845 writes recent.json through it)"),
    ("fuzzlab/disco/capture.py", "JsonlTail.lines", "open()"): (
        1, _NOT_A_STORE + "a disco capture JSONL file"),
    ("fuzzlab/disco/capture.py", "append_record", "open()"): (
        1, _NOT_A_STORE + "a disco capture JSONL file"),
    ("fuzzlab/greybox/coverage.py", "FileCoverageSource.lines_for", ".read_text()"): (
        1, _NOT_A_STORE + "a coverage JSON file" + _CLI),
    ("fuzzlab/greybox/dbfault.py", "FileDbFaultSource.fault_for", ".read_text()"): (
        1, _NOT_A_STORE + "a database-fault JSON file" + _CLI),
    ("fuzzlab/greybox/greybox_cli.py", "_cookie_for", ".open()"): (
        1, _NOT_A_STORE + "the operator's cookie file" + _CLI),
    ("fuzzlab/harness/auto_cli.py", "_account_values", ".open()"): (
        1, _NOT_A_STORE + "the account values file" + _CLI),
    ("fuzzlab/harness/auto_cli.py", "_precheck_peer", ".open()"): (
        1, _NOT_A_STORE + "the peer account file" + _CLI),
    ("fuzzlab/labels/contract.py", "_load_expected_csv", ".open()"): (
        1, _NOT_A_STORE + "a ground-truth CSV"),
    ("fuzzlab/labels/contract.py", "_load_schema", ".read_text()"): (
        1, _NOT_A_STORE + "a packaged JSON schema"),
    ("fuzzlab/labels/contract.py", "load", ".read_text()"): (
        1, _NOT_A_STORE + "a ground-truth labels.json"),
    ("fuzzlab/labels/contract.py", "load_injection_points", ".read_text()"): (
        1, _NOT_A_STORE + "a ground-truth injection-points JSON"),
    ("fuzzlab/labels/contract.py", "load_labels", ".read_text()"): (
        1, _NOT_A_STORE + "a ground-truth labels JSON"),
    ("fuzzlab/labgen/cli.py", "write_tree", ".write_bytes()"): (
        1, _NOT_A_STORE + "a generated application's source files" + _LAB),
    ("fuzzlab/labgen/conformance/tier0.py", "lint_php", ".write_bytes()"): (
        1, _NOT_A_STORE + "a temporary source file to lint" + _LAB),
    ("fuzzlab/labgen/conformance/tier0.py", "lint_python", ".write_bytes()"): (
        1, _NOT_A_STORE + "a temporary source file to lint" + _LAB),
    ("fuzzlab/labgen/conformance/tier0.py", "lint_ruby", ".write_bytes()"): (
        1, _NOT_A_STORE + "a temporary source file to lint" + _LAB),
    ("fuzzlab/labgen/corpus_analysis.py", "write_corpus_report", ".write_text()"): (
        1, _NOT_A_STORE + "a corpus report" + _LAB),
    ("fuzzlab/labgen/identity.py", "load_identities", ".read_text()"): (
        1, _NOT_A_STORE + "an identities YAML/JSON file" + _LAB),
    ("fuzzlab/labgen/identity.py", "load_identities_schema", ".read_text()"): (
        1, _NOT_A_STORE + "a packaged JSON schema" + _LAB),
    ("fuzzlab/labgen/schema.py", "load_manifest", ".read_text()"): (
        1, _NOT_A_STORE + "a lab manifest" + _LAB),
    ("fuzzlab/labgen/schema.py", "load_manifest_schema", ".read_text()"): (
        1, _NOT_A_STORE + "a packaged JSON schema" + _LAB),
    ("fuzzlab/labgen/secret_scanner.py", "_parse_report", ".read_text()"): (
        1, _NOT_A_STORE + "a secret scanner's JSON report" + _LAB),
    ("fuzzlab/labgen/secret_scanner.py", "_write_tree", ".write_bytes()"): (
        1, _NOT_A_STORE + "a generated source tree to scan" + _LAB),
    ("fuzzlab/labgen/verdict.py", "load_safety_matrix", ".read_text()"): (
        1, _NOT_A_STORE + "a safety matrix" + _LAB),
    ("fuzzlab/labgen/verdict.py", "load_safety_matrix_schema", ".read_text()"): (
        1, _NOT_A_STORE + "a packaged JSON schema" + _LAB),
    ("fuzzlab/labgen/zap_oracle.py", "_load_alerts", ".read_text()"): (
        1, _NOT_A_STORE + "a ZAP JSON report" + _LAB),
    ("fuzzlab/labgen/zap_oracle.py", "run_zap_whole_app_scan", "open()"): (
        1, _NOT_A_STORE + "the descriptor of its own new temporary plan file" + _LAB),
    ("fuzzlab/labgen/zap_oracle.py", "run_zap_whole_app_scan", "tempfile.mkstemp()"): (
        1, _NOT_A_STORE + "a new temporary plan file (O_EXCL)" + _LAB),
    ("fuzzlab/mutation/filtermodel.py", "FilterModel.from_rules_file", ".read_text()"): (
        1, _NOT_A_STORE + "a filter rules JSON"),
    ("fuzzlab/procutil.py", "_Supervisor.run.child_setup", "open()"): (
        1, _NOT_A_STORE + "/proc/self/oom_score_adj, in a child before exec"),
    ("fuzzlab/procutil.py", "_listen_table", "open()"): (
        1, _NOT_A_STORE + "/proc/<pid>/net/tcp*"),
    ("fuzzlab/procutil.py", "_read_oom", "open()"): (
        1, _NOT_A_STORE + "/proc/<pid>/oom_score_adj"),
    ("fuzzlab/procutil.py", "read_stat", "open()"): (1, _NOT_A_STORE + "/proc/<pid>/stat"),
    ("fuzzlab/proxy/ca.py", "LocalCA.ensure_ca", ".read_bytes()"): (
        2, _NOT_A_STORE + "the proxy CA's certificate and key"),
    ("fuzzlab/scheduler/context.py", "catalog_priors", ".read_text()"): (
        1, _NOT_A_STORE + "a payload catalog file"),
    ("fuzzlab/session/cli.py", "main", ".open()"): (
        1, "CredentialStore.open, a method, not a file (AU-SESS403's file)"),
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
    ("fuzzlab/web/app.py", "create_app", "StaticFiles()"): (
        1, _NOT_A_STORE + "the package's own static directory (`_STATIC_DIR`)"),
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
    """PA-0535: in the web process's code -- every module the web package imports,
    transitively -- a file is opened outside SQLite only at a reviewed site that never
    touches a store's files. Whether a file is SQLite is asked of SQLite
    (`core.store.open_read_only`, `is_sqlite`; FR-CORE-508)."""
    assert len(web_scope(REPO)) > 150                     # the closure, not a hand list
    assert _mismatch(scan()) == []


def _tree(tmp_path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_the_store_file_guard_catches_synthetic_offenders(tmp_path):
    """PA-0034(2): each raw-open shape is found, library openers included, under an alias
    or an imported name too (``import shutil as sh``, ``from os import open as o``,
    ``io.FileIO``); a helper a
    route reaches by a lazy import or a literal `import_module` is in scope whether or
    not it opens SQLite (the confirming review's `core/secretfile.py` case); a module the
    web package never imports is not; an allowed site passes; a new site in an allowed
    function and a stale allowance both fail."""
    root = _tree(tmp_path, {
        "fuzzlab/__init__.py": "",
        "fuzzlab/web/__init__.py": "",
        "fuzzlab/web/page.py": (
            "import importlib\n"
            "def route(p):\n"
            "    from fuzzlab.core import helper\n"
            "    importlib.import_module('fuzzlab.core.later')\n"
            "    return helper.check(p)\n"),
        "fuzzlab/web/direct.py": (
            "import filecmp, io, os, shutil, tarfile, tempfile, zipfile\n"
            "from pathlib import Path\n"
            "from zipfile import ZipFile\n"
            "from starlette.responses import FileResponse\n"
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
            "    os.fdopen(3)\n"
            "def library(p, d):\n"
            "    shutil.copytree(d, d + '.copy')\n"
            "    filecmp.cmp(p, p + '.bak')\n"
            "    tempfile.mkstemp()\n"
            "    with zipfile.ZipFile(d + '.zip', 'w') as z:\n"
            "        z.write(p)\n"
            "    t = tarfile.open(d + '.tar', 'w')\n"
            "    t.add(p)\n"
            "    return FileResponse(p)\n"
            "def near_misses(fh, z2, p):\n"
            "    fh.write(b'x')                       # a file object's write, not a name\n"
            "    z2.write(p)                          # not bound to an archive here\n"
            "    os.pidfd_open(1)                     # a process descriptor\n"),
        "fuzzlab/web/aliased.py": (                # an opener under another name
            "import io\n"
            "import shutil as sh\n"
            "from io import FileIO\n"
            "from os import open as o\n"
            "from shutil import copyfile\n"
            "from fuzzlab.core.helper import check as copy2\n"
            "def aliased(p):\n"
            "    sh.copy2(p, p + '.bak')\n"
            "    copyfile(p, p + '.bak')\n"
            "    o(p, 0)\n"
            "    io.FileIO(p).close()\n"
            "    FileIO(p).close()\n"
            "    copy2(p)                             # a fuzzlab name, not shutil's\n"),
        "fuzzlab/core/__init__.py": "",
        "fuzzlab/core/helper.py": (                # no SQLite here: still in scope
            "from fuzzlab.core import secret\n"
            "def check(p):\n"
            "    return secret.write(p)\n"),
        "fuzzlab/core/secret.py": (
            "import os\n"
            "def write(p):\n"
            "    os.close(os.open(p, os.O_WRONLY | os.O_CREAT))\n"),
        "fuzzlab/core/later.py": (
            "def read(p):\n"
            "    return open(p).read()\n"),
        "fuzzlab/core/unused.py": (                # never imported by the web package
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
        ("fuzzlab/web/direct.py", "library", "shutil.copytree()"): 1,
        ("fuzzlab/web/direct.py", "library", "filecmp.cmp()"): 1,
        ("fuzzlab/web/direct.py", "library", "tempfile.mkstemp()"): 1,
        ("fuzzlab/web/direct.py", "library", "ZipFile()"): 1,
        ("fuzzlab/web/direct.py", "library", "ZipFile.write()"): 1,
        ("fuzzlab/web/direct.py", "library", ".open()"): 1,          # tarfile.open
        ("fuzzlab/web/direct.py", "library", "TarFile.add()"): 1,
        ("fuzzlab/web/direct.py", "library", "FileResponse()"): 1,
        ("fuzzlab/web/aliased.py", "aliased", "shutil.copy2()"): 1,
        ("fuzzlab/web/aliased.py", "aliased", "shutil.copyfile()"): 1,
        ("fuzzlab/web/aliased.py", "aliased", "os.open()"): 1,
        ("fuzzlab/web/aliased.py", "aliased", "io.FileIO()"): 2,
        ("fuzzlab/core/secret.py", "write", "os.open()"): 1,       # a helper's helper
        ("fuzzlab/core/later.py", "read", "open()"): 1,            # import_module("...")
    })                                                            # core/unused.py: out
    allowed = {k: (n, "synthetic") for k, n in found.items()}
    assert _mismatch(found, allowed) == []
    grown = found + Counter({("fuzzlab/core/secret.py", "write", "os.open()"): 1})
    assert _mismatch(grown, allowed) == [
        "('fuzzlab/core/secret.py', 'write', 'os.open()'): 2 raw open(s), not allowed"]
    stale = {**allowed, ("fuzzlab/web/gone.py", "f", "open()"): (1, "synthetic")}
    assert _mismatch(found, stale) == ["('fuzzlab/web/gone.py', 'f', 'open()'): stale allowance"]
    assert _mismatch(found, {}) != []


# --- the run-time audit hook (tests/_store_audit.py), proven on synthetic offenders -------

_HELPER = """
import os, shutil, zipfile
from pathlib import Path

def summary_7ebf48a(p):                 # BUG-0535's own shape: the Projects listing's read
    with open(p, "rb") as fh:
        return fh.read(16)

def side_file(p):
    return Path(str(p) + "-wal").read_bytes()

def low_level(p):
    os.close(os.open(p, os.O_RDONLY))

def through_a_library(p, dst):
    shutil.copyfile(p, dst)
    with zipfile.ZipFile(dst + ".zip", "w") as z:
        z.write(p)

def route(p):                           # a route handing the path to a helper
    return summary_7ebf48a(p)

def create(p):                          # an allowed name: a new inode created O_EXCL
    os.close(os.open(str(p) + ".new", os.O_CREAT | os.O_EXCL | os.O_WRONLY))

def not_a_store(p):
    return open(p).read()
"""


def test_the_store_open_audit_catches_synthetic_offenders(tmp_path):
    """PA-0034(2) for the audit hook: a production frame's open of a store's main file, its
    -wal or its -shm is caught -- BUG-0535's own read, a helper a route hands the path to,
    `os.open`, a library (`shutil`, `zipfile`) -- through the real audit event; a test's
    own open, an allowed function and a file that is not a store are not."""
    import importlib.util

    from tests import _store_audit
    prod = tmp_path / "prod"
    prod.mkdir()
    (prod / "helper.py").write_text(_HELPER)
    spec = importlib.util.spec_from_file_location("au_sitetree_helper", prod / "helper.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    store = tmp_path / "s.fuzzlab"
    held = Store(store)                         # recorded by the hook: SQLite opened it
    held.start_run("t", "h")
    plain = tmp_path / "plain.json"
    plain.write_text("{}")
    rel = "prod/helper.py"
    monitor = _store_audit.arm(_store_audit.StoreOpenAudit(
        roots=[prod], allowed={(rel, "create")}, repo=tmp_path))
    try:
        open(store, "rb").close()                         # the test's own: not counted
        helper.not_a_store(str(plain))
        helper.create(str(store))
        assert monitor.found == []
        helper.route(str(store))
        helper.side_file(str(store))
        helper.low_level(str(store))
        helper.through_a_library(str(store), str(tmp_path / "copy.db"))
    finally:
        found = _store_audit.disarm(monitor)
        held.close()
    who = [f.split(" opened ")[0] for f in found]
    assert who == [f"{rel}::summary_7ebf48a", f"{rel}::side_file", f"{rel}::low_level",
                   f"{rel}::through_a_library", f"{rel}::through_a_library"], found
    assert all(os.path.realpath(store) in f for f in found)


def test_the_store_open_audit_knows_a_store_opened_by_uri_and_a_live_wal_file(tmp_path):
    """The hook's notion of a store: a database SQLite opened through a `file:` URI (the
    read-only opener's, quoted), and any file with a live -wal beside it even if this
    process never connected to it (another process's store)."""
    from fuzzlab.core.store import open_read_only
    from tests import _store_audit
    a = tmp_path / "a b#.db"                              # quoted in its URI
    with Store(a) as s:
        s.start_run("t", "h")
    _store_audit._stores.discard(os.path.realpath(a))    # only the URI open counts below
    conn = open_read_only(a, timeout=1.0)
    conn.close()
    mon = _store_audit.StoreOpenAudit()
    assert mon.store_of(os.path.realpath(a)) == os.path.realpath(a)
    assert mon.store_of(os.path.realpath(str(a) + "-shm")) == os.path.realpath(a)
    other = tmp_path / "other.db"
    other.write_bytes(b"")
    (tmp_path / "other.db-wal").write_bytes(b"")
    assert mon.store_of(os.path.realpath(other)) == os.path.realpath(other)
    assert mon.store_of(os.path.realpath(tmp_path / "plain.json")) is None
