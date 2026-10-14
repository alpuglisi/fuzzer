"""Every listener binds loopback only, through one gate (BUG-0080, D11, FR-CORE-25,
PA-0081).

`fuzzlab proxy --host 0.0.0.0` bound every interface: the web panel and the OOB
listener each had their own loopback check, and the proxy CLI had none.
"""

from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

import pytest

from fuzzlab.core.net import is_loopback_host, require_loopback

PKG = Path(__file__).resolve().parent.parent / "fuzzlab"
REPO = PKG.parent
_LITERAL_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "[::1]", "localhost",
                                  "LOCALHOST", "::ffff:127.0.0.1"])
def test_loopback_hosts(host):
    assert is_loopback_host(host) and require_loopback(host) == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "lab.local",
                                  "", "example.com", "::ffff:10.0.0.1"])
def test_non_loopback_hosts(host):
    assert not is_loopback_host(host)
    with pytest.raises(ValueError):
        require_loopback(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::", "lab.local"])
def test_the_proxy_cli_refuses_a_non_loopback_bind(host, capsys, monkeypatch):
    import fuzzlab.proxy.cli as cli
    started = []

    async def fake_start(self):
        started.append(self.host)
        raise RuntimeError("must not be reached")
    monkeypatch.setattr(cli.AsyncProxyServer, "start", fake_start)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--authorized", "--host", host, "--port", "0", "--no-tls"])
    assert exc.value.code == 2 and "non-loopback" in capsys.readouterr().err
    assert started == []


def test_the_proxy_server_itself_refuses_a_non_loopback_bind():
    from fuzzlab.proxy.scope import Scope
    from fuzzlab.proxy.server import AsyncProxyServer, ProxyEngine
    srv = AsyncProxyServer(ProxyEngine(scope=Scope(), sender=lambda *a: b""),
                           host="0.0.0.0", port=0)
    with pytest.raises(ValueError):
        asyncio.run(srv.start())


def test_the_in_process_proxy_and_oob_refuse_too():
    from fuzzlab.oracle.oob import OobListener
    from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController
    with pytest.raises(ValueError):
        ProxyController(ProxyConfig(host="0.0.0.0")).build()
    with pytest.raises(ValueError):
        OobListener(host="0.0.0.0")
    OobListener(host="127.0.0.2")                  # any 127/8 is loopback (superset)


# --- the guard: every listener call site is gated -----------------------------

_LISTENER_CALLS = {"start_server", "HTTPServer", "ThreadingHTTPServer", "TCPServer",
                   "bind", "run"}


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


_PROCUTIL_LAUNCHERS = {"start_server", "astart_server", "run_bounded"}


def _defines(tree: ast.AST) -> set[str]:
    return {n.name for n in getattr(tree, "body", [])
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _is_procutil_launch(node: ast.Call, local_defs: set[str]) -> bool:
    """``procutil.start_server`` / ``astart_server`` / ``run_bounded`` -- or the bare
    name inside the module that defines it (``fuzzlab/procutil.py``) -- launches a
    process; it does not listen (BUG-0130: the guard's false positive). The servers it
    launches are covered by :func:`server_launch_problems` and the runtime check."""
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr in _PROCUTIL_LAUNCHERS and getattr(f.value, "id", "") == "procutil"
    return isinstance(f, ast.Name) and f.id in _PROCUTIL_LAUNCHERS and f.id in local_defs


def _is_listener(node: ast.Call, local_defs: frozenset = frozenset()) -> bool:
    name = _callee(node)
    if name == "run":                               # only uvicorn.run
        return isinstance(node.func, ast.Attribute) and \
            getattr(node.func.value, "id", "") == "uvicorn"
    if _is_procutil_launch(node, set(local_defs)):
        return False
    return name in _LISTENER_CALLS


def _literal_loopback(node: ast.Call) -> bool:
    """A literal loopback host in the call: `bind(("127.0.0.1", 0))`, `HTTPServer((
    "127.0.0.1", 0), …)`."""
    for arg in node.args:
        if isinstance(arg, ast.Tuple) and arg.elts and isinstance(arg.elts[0], ast.Constant):
            return arg.elts[0].value in _LITERAL_LOOPBACK
    return False


def _gate_calls(tree: ast.AST) -> bool:
    return any(isinstance(n, ast.Call) and _callee(n) in ("require_loopback",
                                                          "is_loopback_host")
               for n in ast.walk(tree))


def listener_problems(source: str, filename: str = "<mem>") -> list[str]:
    tree = ast.parse(source)
    local_defs = frozenset(_defines(tree))
    out = []
    parents: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[c] = p
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_listener(node, local_defs)):
            continue
        if _literal_loopback(node):
            continue
        scope, gated = node, False
        while scope in parents:                     # the function, then its class
            scope = parents[scope]
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                    and _gate_calls(scope):
                gated = True
                break
        if not gated:
            out.append(f"{filename}:{node.lineno} {_callee(node)}")
    return out


def test_every_listener_in_fuzzlab_is_gated():
    problems = []
    for path in sorted(PKG.rglob("*.py")):
        problems += listener_problems(path.read_text(encoding="utf-8"),
                                      str(path.relative_to(PKG)))
    assert problems == []


def test_every_listener_in_the_tests_is_gated_too():
    """BUG-0130 sweep: the tests' own in-process and child-process listeners (marker
    servers, OOB fixtures, the no-ML child's uvicorn) bind loopback or pass the gate."""
    problems = []
    for path in sorted((REPO / "tests").rglob("*.py")):
        problems += listener_problems(path.read_text(encoding="utf-8"),
                                      path.relative_to(REPO).as_posix())
    assert problems == []


def test_the_guard_flags_an_ungated_listener():
    offender = ("import asyncio\n"
                "async def serve(host):\n"
                "    await asyncio.start_server(lambda r, w: None, host, 8080)\n")
    assert listener_problems(offender) == ["<mem>:3 start_server"]
    gated = ("import asyncio\nfrom fuzzlab.core.net import require_loopback\n"
             "async def serve(host):\n    require_loopback(host)\n"
             "    await asyncio.start_server(lambda r, w: None, host, 8080)\n")
    assert listener_problems(gated) == []


def test_a_procutil_launch_is_not_a_listener_but_asyncio_start_server_still_is():
    """BUG-0130: the guard flagged ``procutil.start_server`` (a process launcher) as
    ``asyncio.start_server``. A launcher is exempt; a real ``start_server`` is not."""
    launch = ("from fuzzlab import procutil\n"
              "def boot(port):\n"
              "    return procutil.start_server(['php', '-S', f'127.0.0.1:{port}'])\n")
    assert listener_problems(launch) == []
    own = ("def start_server(argv):\n    pass\n"
           "def run_bounded(argv):\n    return start_server(argv)\n")
    assert listener_problems(own) == []
    still = ("import asyncio\n"
             "async def serve(host):\n"
             "    await asyncio.start_server(lambda r, w: None, host, 8080)\n")
    assert listener_problems(still) == ["<mem>:3 start_server"]


# --- BUG-0130: every server launched through procutil pins loopback ------------------

_LOOPBACK_LITERAL = re.compile(r"127\.0\.0\.1|\blocalhost\b|(?<![0-9a-fA-F:])::1\b")
_WILDCARD_LITERAL = re.compile(r"\b0\.0\.0\.0\b")

#: Launch sites that do not start a lab server (file -> (count, reason)). Exact counts.
NON_SERVER_LAUNCHES = {
    "fuzzlab/procutil.py": (2, "run_bounded / arun_bounded launch a forking tool (npm, go, mvn, "
                               "composer, bundle, the corpus sync's VCS client, labctl.sh ps), "
                               "not a server"),
    "fuzzlab/web/runner.py": (1, "launcher jobs are fuzzlab CLI commands; their own listeners go "
                                 "through core.net.require_loopback (the listener guard above)"),
    "tests/test_procutil.py": (None, "process-tree tests (sleep, sh, python -c ...); its listener "
                                     "tests bind a literal host inside the program on purpose, "
                                     "0.0.0.0 included, to prove the runtime check"),
}


def _strings(node: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return out


def _launch_expressions(call: ast.Call) -> list[ast.AST]:
    exprs = list(call.args[:1])
    exprs += [k.value for k in call.keywords if k.arg in ("env", "argv")]
    return exprs


def _pin_strings(call: ast.Call, func: ast.AST | None, module: ast.Module) -> list[str]:
    """String literals that decide where the launched server binds: in its argv and
    ``env=`` expressions, in same-module helpers those expressions call, and in the
    enclosing function's assignments to names they use (``env["HOST"] = ...``)."""
    helpers = {n.name: n for n in module.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    exprs = _launch_expressions(call)
    out = []
    names = set()
    for e in exprs:
        out += _strings(e)
        for n in ast.walk(e):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in helpers:
                out += _strings(helpers[n.func.id])
            if isinstance(n, ast.Name):
                names.add(n.id)
    if func is not None and names:
        for n in ast.walk(func):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    base = t.value if isinstance(t, ast.Subscript) else t
                    if isinstance(base, ast.Name) and base.id in names:
                        out += _strings(n)
    return out


def server_launch_problems(source: str, filename: str = "<mem>") -> list[str]:
    """Every ``procutil.start_server`` / ``astart_server`` call must pin loopback in its
    argv or env (a literal, or a same-module helper / assignment), and never name a
    wildcard address."""
    tree = ast.parse(source)
    local_defs = _defines(tree)
    parents: dict[ast.AST, ast.AST] = {}
    for p_ in ast.walk(tree):
        for c in ast.iter_child_nodes(p_):
            parents[c] = p_
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_procutil_launch(node, local_defs)
                and _callee(node) in ("start_server", "astart_server")):
            continue
        func = node
        while func in parents and not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func = parents[func]
        func = func if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        strings = _pin_strings(node, func, tree)
        if any(_WILDCARD_LITERAL.search(x) for x in strings) or not any(
                _LOOPBACK_LITERAL.search(x) for x in strings):
            out.append(f"{filename}:{node.lineno} {_callee(node)}")
    return out


def test_every_server_launched_through_procutil_pins_loopback():
    problems = []
    for top in ("fuzzlab", "tests"):
        for path in sorted((REPO / top).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            found = server_launch_problems(path.read_text(encoding="utf-8"), rel)
            allowed = NON_SERVER_LAUNCHES.get(rel)
            if allowed is not None:
                count = allowed[0]
                if count is not None and len(found) != count:
                    problems.append(f"{rel}: {len(found)} unpinned launches, allowlisted {count}")
                continue
            problems += found
    assert problems == [], ("a server launched through procutil must bind loopback explicitly "
                            "(BUG-0130, PA-0130):\n" + "\n".join(problems))


@pytest.mark.parametrize("src", [
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['java', '-jar', 'app.jar', f'--server.port={port}'])\n",
    "import os\nfrom fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['node', 'app.js'], env={**os.environ, 'PORT': str(port)})\n",
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    env = {'PORT': str(port)}\n"
    "    return procutil.start_server(['./server'], env=env)\n",
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['php', '-S', f'0.0.0.0:{port}'])\n",
    "from fuzzlab import procutil\n"
    "async def boot(port):\n"
    "    return await procutil.astart_server(['node', 'app.js', '--host', '0.0.0.0'])\n",
    # a loopback pin elsewhere does not excuse a wildcard bind
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['php', '-S', f'0.0.0.0:{port}'], env={'HOST': '127.0.0.1'})\n",
])
def test_the_pin_rule_flags_synthetic_offenders(src):
    assert server_launch_problems(src), src


@pytest.mark.parametrize("src", [
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['java', '-jar', 'a.jar', '--server.address=127.0.0.1'])\n",
    "import os\nfrom fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['node', 'app.js'], env={**os.environ, 'HOST': '127.0.0.1'})\n",
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    env = dict()\n"
    "    env['HOST'] = '127.0.0.1'\n"
    "    return procutil.start_server(['./server'], env=env)\n",
    "from fuzzlab import procutil\n"
    "def _argv(port):\n"
    "    return ['php', '-S', f'127.0.0.1:{port}']\n"
    "def boot(port):\n"
    "    return procutil.start_server(_argv(port))\n",
])
def test_the_pin_rule_passes_pinned_launches(src):
    assert server_launch_problems(src) == [], src
