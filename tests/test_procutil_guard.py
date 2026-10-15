"""AST guard for BUG-0125 / PA-0125: every long-lived child process in ``fuzzlab/`` and
``tests/`` is started through ``fuzzlab.procutil`` (supervised, tied to its owner,
stopped as a whole tree, identity-checked).

Flagged, anywhere outside ``fuzzlab/procutil.py`` and the reasoned allowlist below:

* any direct spawn primitive -- ``subprocess.Popen``, ``asyncio.create_subprocess_exec``
  / ``_shell``, ``loop.subprocess_exec`` / ``_shell``, ``os.fork`` / ``forkpty`` /
  ``posix_spawn[p]`` -- however it is imported or aliased;
* ``subprocess.run`` / ``call`` / ``check_call`` / ``check_output`` of a tool that
  forks (``npm``, ``go``, ``mvn``, ...) with a ``timeout=``: on timeout ``subprocess``
  kills only the direct child and the tool's children survive (``go run``'s built
  binary, npm's scripts). Use ``procutil.run_bounded``.

Proven on synthetic offenders (PA-0034(2)); a stale allowlist entry fails too.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

SPAWN_ATTRS = {"Popen", "create_subprocess_exec", "create_subprocess_shell",
               "subprocess_exec", "subprocess_shell", "fork", "forkpty",
               "posix_spawn", "posix_spawnp"}
SPAWN_MODULES = {"subprocess", "asyncio", "os", "pty", "asyncio.subprocess"}
RUN_FUNCS = {"run", "call", "check_call", "check_output"}
FORKING_TOOLS = {"npm", "npx", "go", "mvn", "gradle", "composer", "bundle", "cargo", "make",
                 # CC-CORE-0300: a shell runs whatever its script forks, and a container CLI
                 # (compose above all) forks helpers -- a timeout must take the whole tree.
                 "bash", "sh", "docker", "podman", "docker-compose", "podman-compose"}

#: file -> (number of flagged sites, reason). Exact counts: a new site in an
#: allowlisted file fails, and so does an entry that no longer matches.
ALLOWLIST: dict[str, tuple[int, str]] = {
    "fuzzlab/procutil.py": (
        2, "the sanctioned implementation: the supervisor's Popen (owner side, sync and "
           "asyncio alike -- asyncio's own spawn would reap the supervisor before the sweep, "
           "review M2) and the supervisor's own single-threaded spawn of the server"),
    "fuzzlab/tools/corpus_validation_sandbox.py": (
        1, "BUG-0125 D14: keeps runsc's own lifecycle (its pid is attached to cgroups at once); "
           "started in its own session and its timeout kills the whole group through "
           "procutil.kill_process_group"),
    "tests/test_procutil.py": (
        3, "the owner processes the owner-death tests SIGKILL and reap themselves, the "
           "bystander `sleep` of the reused-pid identity test (it must NOT be ours), and a "
           "direct run of the supervisor entry point with a wrong owner (it must refuse)"),
}


def _offences(src: str) -> list[tuple[int, str]]:
    tree = ast.parse(src)
    module_aliases: dict[str, str] = {}   # local name -> module
    func_aliases: dict[str, str] = {}     # local name -> "module.func"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                module_aliases[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                if node.module in SPAWN_MODULES or node.module.startswith("subprocess"):
                    func_aliases[a.asname or a.name] = f"{node.module}.{a.name}"
                if a.name == "subprocess" and node.module == "asyncio":
                    module_aliases[a.asname or a.name] = "asyncio.subprocess"

    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name: str | None = None
        if isinstance(f, ast.Attribute):
            if f.attr in SPAWN_ATTRS and f.attr not in {"fork", "forkpty", "posix_spawn", "posix_spawnp"}:
                name = f.attr
            elif f.attr in SPAWN_ATTRS and isinstance(f.value, ast.Name) and \
                    module_aliases.get(f.value.id) in {"os", "pty"}:
                name = f.attr
            elif f.attr in RUN_FUNCS and isinstance(f.value, ast.Name) and \
                    module_aliases.get(f.value.id) == "subprocess":
                name = "run:" + f.attr
        elif isinstance(f, ast.Name) and f.id in func_aliases:
            target = func_aliases[f.id].rsplit(".", 1)[1]
            if target in SPAWN_ATTRS:
                name = target
            elif target in RUN_FUNCS and func_aliases[f.id].startswith("subprocess."):
                name = "run:" + target
        if name is None:
            continue
        if name.startswith("run:"):
            if not any(k.arg == "timeout" for k in node.keywords):
                continue
            argv = node.args[0] if node.args else None
            if not (isinstance(argv, (ast.List, ast.Tuple)) and argv.elts
                    and isinstance(argv.elts[0], ast.Constant)
                    and str(argv.elts[0].value).rsplit("/", 1)[-1] in FORKING_TOOLS):
                continue
        out.append((node.lineno, name))
    return out


def _scan() -> dict[str, list[tuple[int, str]]]:
    found: dict[str, list[tuple[int, str]]] = {}
    for top in ("fuzzlab", "tests"):
        for path in sorted((REPO / top).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            hits = _offences(path.read_text(encoding="utf-8"))
            if hits:
                found[rel] = hits
    return found


def test_every_child_process_goes_through_procutil() -> None:
    found = _scan()
    problems = []
    for rel, hits in found.items():
        allowed = ALLOWLIST.get(rel)
        if allowed is None or allowed[0] != len(hits):
            problems.append(f"{rel}: {hits} (allowlisted: {allowed[0] if allowed else 0})")
    for rel in ALLOWLIST:
        if rel not in found:
            problems.append(f"stale allowlist entry: {rel}")
    assert not problems, ("spawn outside fuzzlab.procutil (BUG-0125, PA-0125) -- use "
                          "procutil.start_server / astart_server / run_bounded:\n" + "\n".join(problems))


@pytest.mark.parametrize("src", [
    "import subprocess\nsubprocess.Popen(['node', 'app.js'])\n",
    "import subprocess as sp\np = sp.Popen(['php', '-S', 'x'])\n",
    "from subprocess import Popen\nPopen(['java', '-jar', 'x.jar'])\n",
    "from subprocess import Popen as P\nP(['x'])\n",
    "import asyncio\nasync def f():\n    await asyncio.create_subprocess_exec('x')\n",
    "from asyncio import create_subprocess_shell\nasync def f():\n    await create_subprocess_shell('x')\n",
    "async def f(loop):\n    await loop.subprocess_exec(lambda: None, 'x')\n",
    "import os\nos.fork()\n",
    "import os\nos.posix_spawn('/bin/x', ['x'], {})\n",
    "import subprocess\nsubprocess.run(['go', 'run', 'main.go'], timeout=5)\n",
    "import subprocess\nsubprocess.check_output(['npm', 'install'], timeout=5)\n",
    "from subprocess import run\nrun(['/usr/bin/mvn', 'package'], timeout=5)\n",
    "import subprocess\nsubprocess.run(['bash', '-c', 'x'], timeout=5)\n",
    "import subprocess\nsubprocess.run(\n    ['sh', 'x.sh'], capture_output=True, timeout=5)\n",
    "import subprocess\nsubprocess.run(['docker', 'compose', 'up'], timeout=5)\n",
    "from subprocess import check_output\ncheck_output(['/usr/bin/podman', 'ps'], timeout=5)\n",
    "import subprocess\nsubprocess.call(['docker-compose', 'up'], timeout=5)\n",
    "import subprocess\nsubprocess.run(['podman-compose', 'up'], timeout=5)\n",
])
def test_guard_flags_synthetic_offenders(src: str) -> None:
    assert _offences(src), src


@pytest.mark.parametrize("src", [
    "from fuzzlab import procutil\nprocutil.start_server(['node', 'app.js'])\n",
    "from fuzzlab import procutil\nprocutil.run_bounded(['go', 'build'], timeout=5)\n",
    "import subprocess\nsubprocess.run(['php', '-l', 'x.php'], timeout=5)\n",  # does not fork
    "import subprocess\nsubprocess.run(['go', 'version'])\n",  # no timeout: waits for the tree
    "import os\nos.kill(1, 0)\n",
])
def test_guard_passes_sanctioned_and_non_forking_calls(src: str) -> None:
    assert _offences(src) == [], src


# --- the leaf rule: procutil imports nothing from fuzzlab, and only the stdlib ------

def test_procutil_is_a_stdlib_only_leaf() -> None:
    import sys

    tree = ast.parse((REPO / "fuzzlab" / "procutil.py").read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    roots.discard("__future__")
    assert roots <= set(sys.stdlib_module_names), roots - set(sys.stdlib_module_names)


#: Beyond itself, labgen imports only the label contract (pre-existing) and procutil.
LABGEN_ALLOWED = ("fuzzlab.labgen", "fuzzlab.labels", "fuzzlab.procutil")


def _labgen_import_offences(src: str) -> list[str]:
    bad = []
    for node in ast.walk(ast.parse(src)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module] if node.module != "fuzzlab" else [f"fuzzlab.{a.name}" for a in node.names]
        for n in names:
            if (n == "fuzzlab" or n.startswith("fuzzlab.")) and not any(
                    n == ok or n.startswith(ok + ".") for ok in LABGEN_ALLOWED):
                bad.append(n)
    return bad


def test_labgen_imports_only_itself_the_label_contract_and_procutil() -> None:
    problems = {}
    for path in sorted((REPO / "fuzzlab" / "labgen").rglob("*.py")):
        bad = _labgen_import_offences(path.read_text(encoding="utf-8"))
        if bad:
            problems[path.relative_to(REPO).as_posix()] = bad
    assert not problems, problems


@pytest.mark.parametrize("src", [
    "from fuzzlab.core import http\n",
    "import fuzzlab.oracle\n",
    "from fuzzlab import web\n",
])
def test_labgen_import_guard_flags_synthetic_offenders(src: str) -> None:
    assert _labgen_import_offences(src)


def test_labgen_import_guard_allows_procutil() -> None:
    assert _labgen_import_offences("from fuzzlab import procutil\nimport fuzzlab.labels.contract\n") == []
