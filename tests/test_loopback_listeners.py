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


_PROCUTIL_LAUNCHERS = {"start_server", "astart_server", "run_bounded",
                       "start_server_on_free_port"}  # BUG-0143: a launch too


def _defines(tree: ast.AST) -> set[str]:
    return {n.name for n in getattr(tree, "body", [])
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def procutil_aliases(tree: ast.AST) -> tuple[set[str], dict[str, str]]:
    """Alias-proof launch detection (review B3 (c)/(d)): the local names bound to the
    ``fuzzlab.procutil`` module, and local names bound to its launchers
    (``from fuzzlab.procutil import start_server as ss``)."""
    modules: set[str] = set()
    funcs: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "fuzzlab":
            for a in n.names:
                if a.name == "procutil":
                    modules.add(a.asname or "procutil")
        elif isinstance(n, ast.ImportFrom) and n.module == "fuzzlab.procutil":
            for a in n.names:
                if a.name in _PROCUTIL_LAUNCHERS:
                    funcs[a.asname or a.name] = a.name
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "fuzzlab.procutil" and a.asname:
                    modules.add(a.asname)
    return modules, funcs


def launch_name(node: ast.Call, local_defs: set[str], aliases) -> str | None:
    """The procutil launcher a call reaches -- through ``procutil.x``, a module alias
    (``pu.x``), ``fuzzlab.procutil.x``, an imported alias (``ss``), or the bare name
    inside the module defining it -- else None."""
    modules, funcs = aliases
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr in _PROCUTIL_LAUNCHERS:
        v = f.value
        if isinstance(v, ast.Name) and v.id in modules:
            return f.attr
        if isinstance(v, ast.Attribute) and v.attr == "procutil" and getattr(v.value, "id", "") == "fuzzlab":
            return f.attr
    if isinstance(f, ast.Name):
        if f.id in funcs:
            return funcs[f.id]
        if f.id in _PROCUTIL_LAUNCHERS and f.id in local_defs:
            return f.id
    return None


def _is_listener(node: ast.Call, local_defs: frozenset = frozenset(), aliases=(set(), {})) -> bool:
    name = _callee(node)
    if name == "run":                               # only uvicorn.run
        return isinstance(node.func, ast.Attribute) and \
            getattr(node.func.value, "id", "") == "uvicorn"
    if launch_name(node, set(local_defs), aliases):  # a process launch, not a listener (BUG-0130)
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


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[c] = p
    return parents


def listener_problems(source: str, filename: str = "<mem>") -> list[str]:
    tree = ast.parse(source)
    local_defs = frozenset(_defines(tree))
    aliases = procutil_aliases(tree)
    out = []
    parents = _parents(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_listener(node, local_defs, aliases)):
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
    ``asyncio.start_server``. A launcher is exempt -- however it is imported -- and a
    real ``start_server`` is not."""
    for launch in ("from fuzzlab import procutil\n"
                   "def boot(port):\n    return procutil.start_server(['x'])\n",
                   "from fuzzlab import procutil as pu\n"
                   "def boot(port):\n    return pu.start_server(['x'])\n",
                   "from fuzzlab.procutil import start_server as ss\n"
                   "def boot(port):\n    return ss(['x'])\n",
                   "def start_server(argv):\n    pass\n"
                   "def run_bounded(argv):\n    return start_server(argv)\n"):
        assert listener_problems(launch) == [], launch
    for still in ("import asyncio\n"
                  "async def serve(host):\n"
                  "    await asyncio.start_server(lambda r, w: None, host, 8080)\n",
                  "from asyncio import start_server\n"
                  "async def serve(host):\n"
                  "    await start_server(lambda r, w: None, host, 8080)\n"):
        assert listener_problems(still) == ["<mem>:3 start_server"], still


# --- BUG-0130: every server launched through procutil pins loopback (a LINT) -------------
#
# The static rule is a lint: it catches a launch site that leaves the bind address to a
# default or the environment. The AUTHORITATIVE check is the runtime one --
# procutil.assert_loopback_only after boot, and at every stop while the server is live.

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
#: argv flags whose next token is the bind host (or host:port).
_HOST_FLAGS = {"-S", "-b", "-H", "--bind", "--host", "--listen", "--address", "runserver"}
#: ``--key=value`` keys that set the bind host.
_HOST_KEYS_ARGV = {"--server.address", "--host", "--bind", "--address", "--listen", "--hostname"}
#: Environment keys that set the bind host (the stacks' documented keys).
_HOST_KEYS_ENV = {"HOST", "BIND", "BIND_ADDRESS", "ADDRESS", "LISTEN_ADDRESS", "SERVER_ADDRESS"}
_WILDCARD_VALUE = re.compile(r"^(0\.0\.0\.0|::|\[::\]|\*|0|)(:.*)?$")
_WILDCARD_ANYWHERE = re.compile(r"://(\*|0\.0\.0\.0|\[::\])|^\*:\d|(^|[=\s])(0\.0\.0\.0|\[::\])(:|$)")

#: Launch sites that do not start a lab server (file -> (count, reason)). Exact counts.
NON_SERVER_LAUNCHES = {
    "fuzzlab/procutil.py": (3, "run_bounded / arun_bounded launch a forking tool (npm, go, mvn, "
                               "composer, bundle, the corpus sync's VCS client, labctl.sh ps), "
                               "not a server; start_server_on_free_port (BUG-0143) delegates "
                               "to start_server, and each of its callers is checked at its "
                               "own call"),
    "fuzzlab/web/runner.py": (1, "launcher jobs are fuzzlab CLI commands; their own listeners go "
                                 "through core.net.require_loopback (the listener guard above)"),
    "tests/test_procutil.py": (None, "process-tree tests (sleep, sh, python -c ...); its listener "
                                     "tests bind a host given in argv on purpose, wildcards only "
                                     "in a private network namespace (the netns rule below)"),
    "tests/test_pytest_lock.py": (1, "starts background pytest sessions on tiny test trees, the "
                                     "subjects of the host pytest lock's tests (BUG-0532); they "
                                     "listen on nothing"),
}


def _text(node: ast.AST) -> str | None:
    """A string token's text: a constant, or an f-string with ``{}`` for each value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return None


def _host_part(value: str) -> str:
    if value.startswith("["):
        return value.split("]")[0] + "]"
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _argv_findings(tokens: list[str | None]) -> tuple[bool, bool]:
    """``(pinned, wildcard)`` for one argv token list. Pin-shaped only (review B3 (a)):
    a host flag followed by a loopback host[:port], ``--key=loopback``, or a token that
    is exactly a loopback host (a positional host argument)."""
    pinned = wildcard = False
    for i, tok in enumerate(tokens):
        if tok is None:
            continue
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok in _HOST_FLAGS and nxt is not None:
            if _host_part(nxt) in _LOOPBACK_HOSTS:
                pinned = True
            elif _WILDCARD_VALUE.match(nxt):
                wildcard = True
        if "=" in tok and tok.split("=", 1)[0] in _HOST_KEYS_ARGV:
            value = tok.split("=", 1)[1]
            if _host_part(value) in _LOOPBACK_HOSTS:
                pinned = True
            elif _WILDCARD_VALUE.match(value):
                wildcard = True
        if tok in _LOOPBACK_HOSTS:
            pinned = True
        if tok in ("0.0.0.0", "::", "[::]") or _WILDCARD_ANYWHERE.search(tok):
            wildcard = True
    return pinned, wildcard


def _env_findings(pairs: list[tuple[str, str | None]]) -> tuple[bool, bool]:
    pinned = wildcard = False
    for key, value in pairs:
        if key not in _HOST_KEYS_ENV or value is None:
            continue
        if _host_part(value) in _LOOPBACK_HOSTS:
            pinned = True
        elif _WILDCARD_VALUE.match(value):
            wildcard = True
    return pinned, wildcard


def _lists(node: ast.AST) -> list[list[str | None]]:
    return [[_text(e) for e in n.elts] for n in ast.walk(node) if isinstance(n, (ast.List, ast.Tuple))]


def _env_pairs(node: ast.AST) -> list[tuple[str, str | None]]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    out.append((k.value, _text(v)))
    return out


def _launch_findings(call: ast.Call, func: ast.AST | None, module: ast.Module) -> tuple[bool, bool]:
    """Pins and wildcards for one launch: its argv (and same-module helpers it calls --
    their list literals only, never docstrings, review B3 (b)), its ``env=`` (dicts,
    and the enclosing function's assignments to a name it uses: ``env["HOST"] = ...``)."""
    helpers = {n.name: n for n in module.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    argv = call.args[0] if call.args else None
    env = next((k.value for k in call.keywords if k.arg in ("env", "env_for")), None)
    token_lists: list[list[str | None]] = []
    env_pairs: list[tuple[str, str | None]] = []
    names: set[str] = set()
    for expr, is_env in ((argv, False), (env, True)):
        if expr is None:
            continue
        if is_env:
            env_pairs += _env_pairs(expr)
        else:
            token_lists += _lists(expr)
        for n in ast.walk(expr):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in helpers:
                body = [s for s in helpers[n.func.id].body
                        if not (isinstance(s, ast.Expr) and isinstance(getattr(s, "value", None), ast.Constant))]
                for s in body:
                    token_lists += _lists(s)
                    env_pairs += _env_pairs(s)
            if isinstance(n, ast.Name):
                names.add(n.id)
    if func is not None and names:
        for n in ast.walk(func):
            if not isinstance(n, ast.Assign):
                continue
            for t in n.targets:
                if isinstance(t, ast.Subscript) and getattr(t.value, "id", None) in names \
                        and isinstance(t.slice, ast.Constant):
                    env_pairs.append((t.slice.value, _text(n.value)))
                elif isinstance(t, ast.Name) and t.id in names:
                    token_lists += _lists(n.value)
                    env_pairs += _env_pairs(n.value)
    pinned = wildcard = False
    for tokens in token_lists:
        p_, w_ = _argv_findings(tokens)
        pinned, wildcard = pinned or p_, wildcard or w_
    p_, w_ = _env_findings(env_pairs)
    return pinned or p_, wildcard or w_


def server_launch_problems(source: str, filename: str = "<mem>") -> list[str]:
    """Every ``procutil.start_server`` / ``astart_server`` call -- however procutil or the
    launcher is imported -- pins loopback in a pin-shaped argv token or env host key,
    and names no wildcard (``0.0.0.0``, ``::``, ``[::]``, ``*``, an empty or ``0``
    host)."""
    tree = ast.parse(source)
    local_defs = _defines(tree)
    aliases = procutil_aliases(tree)
    parents = _parents(tree)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or launch_name(node, local_defs, aliases) not in (
                "start_server", "astart_server", "start_server_on_free_port"):
            continue
        func = node
        while func in parents and not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func = parents[func]
        func = func if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        pinned, wildcard = _launch_findings(node, func, tree)
        if wildcard or not pinned:
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


_PIN_OFFENDERS = {
    "spring port only": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['java', '-jar', 'app.jar', f'--server.port={port}'])\n",
    "node env without HOST": "import os\nfrom fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['node', 'app.js'], env={**os.environ, 'PORT': str(port)})\n",
    "env assigned without HOST": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    env = {'PORT': str(port)}\n"
    "    return procutil.start_server(['./server'], env=env)\n",
    "B3a: a base URL is not a pin": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['java', '-jar', 'a.jar', f'--server.port={port}'],\n"
    "                                 env={'X': 'http://127.0.0.1:8080'})\n",
    "B3b: a docstring is not a pin": "from fuzzlab import procutil\n"
    "def _argv(port):\n"
    "    '''Serve on localhost (127.0.0.1).'''\n"
    "    return ['java', '-jar', 'a.jar', f'--server.port={port}']\n"
    "def boot(port):\n"
    "    return procutil.start_server(_argv(port))\n",
    "B3c: an imported launcher alias": "from fuzzlab.procutil import start_server as ss\n"
    "def boot(port):\n"
    "    return ss(['java', '-jar', 'a.jar', f'--server.port={port}'])\n",
    "B3d: a module alias": "from fuzzlab import procutil as pu\n"
    "def boot(port):\n"
    "    return pu.start_server(['java', '-jar', 'a.jar', f'--server.port={port}'])\n",
    "wildcard 0.0.0.0": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['php', '-S', f'0.0.0.0:{port}'])\n",
    "wildcard despite a pin elsewhere": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['php', '-S', f'0.0.0.0:{port}'], env={'HOST': '127.0.0.1'})\n",
    "A-S1 ::": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '--host', '::', '--bind', '127.0.0.1'])\n",
    "A-S1 [::]": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', f'--bind=[::]:{port}', '--host=127.0.0.1'])\n",
    "A-S1 tcp://*": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '--listen', 'tcp://*:3000', '-b', '127.0.0.1'])\n",
    "A-S1 --bind *": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '--bind', '*', '--host=127.0.0.1'])\n",
    "A-S1 *:8080": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '*:8080', '127.0.0.1'])\n",
    "A-S1 HOST empty": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '127.0.0.1'], env={'HOST': ''})\n",
    "A-S1 HOST=:: (env)": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '127.0.0.1'], env={'HOST': '::'})\n",
    "A-S1 HOST=0": "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    return procutil.start_server(['./server', '127.0.0.1'], env={'HOST': '0'})\n",
    "astart_server wildcard": "from fuzzlab import procutil\n"
    "async def boot(port):\n"
    "    return await procutil.astart_server(['node', 'app.js', '--host', '0.0.0.0'])\n",
}


@pytest.mark.parametrize("name", sorted(_PIN_OFFENDERS))
def test_the_pin_rule_flags_synthetic_offenders(name):
    assert server_launch_problems(_PIN_OFFENDERS[name]), name


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
    "from fuzzlab import procutil as pu\n"
    "def boot(port):\n"
    "    return pu.start_server(['rails', 'server', '-b', '127.0.0.1', '-p', '0'])\n",
    "from fuzzlab.procutil import start_server as ss\n"
    "def boot(port):\n"
    "    return ss(['python', 'manage.py', 'runserver', f'127.0.0.1:{port}'])\n",
])
def test_the_pin_rule_passes_pinned_launches(src):
    assert server_launch_problems(src) == [], src


# --- BUG-0130 review A: every server site checks its real sockets right after boot -----

def boot_check_problems(source: str, filename: str = "<mem>") -> list[str]:
    """Every ``start_server`` / ``astart_server`` call (alias-proof) is followed, in the
    same function -- or, for a launch in ``__init__``, the same method -- by a later call
    to procutil's ``assert_loopback_only``: the rule "checked after boot, and at stop
    while live" (the stop half is ``_stop_core``, which every stop goes through)."""
    tree = ast.parse(source)
    local_defs = _defines(tree)
    aliases = procutil_aliases(tree)
    modules = aliases[0]
    parents = _parents(tree)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or launch_name(node, local_defs, aliases) not in (
                "start_server", "astart_server", "start_server_on_free_port"):
            continue
        func = node
        while func in parents and not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func = parents[func]
        checked = isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "assert_loopback_only"
            and (getattr(n.func.value, "id", None) in modules
                 or getattr(n.func.value, "attr", None) == "procutil")
            and n.lineno > node.lineno
            for n in ast.walk(func))
        if not checked:
            out.append(f"{filename}:{node.lineno} {_callee(node)}")
    return out


def test_every_server_site_checks_loopback_right_after_boot():
    problems = []
    for top in ("fuzzlab", "tests"):
        for path in sorted((REPO / top).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            if rel in NON_SERVER_LAUNCHES:  # no lab server; the stop-time check still runs
                continue
            problems += boot_check_problems(path.read_text(encoding="utf-8"), rel)
    assert problems == [], ("a lab server site must call procutil.assert_loopback_only right "
                            "after boot (BUG-0130, PA-0130):\n" + "\n".join(problems))


def test_a_free_port_launch_is_checked_like_any_other():
    """BUG-0143 moved test sites to ``start_server_on_free_port``. Both BUG-0130 rules
    must still see them: an unpinned argv lambda, a wildcard env, and a missing boot
    check are each flagged, and a pinned, checked launch passes."""
    unpinned = ("from fuzzlab import procutil\n"
                "def boot():\n"
                "    h, port = procutil.start_server_on_free_port(lambda port: ['node', 'app.js'],\n"
                "        boot_timeout=5, env_for=lambda port: {'PORT': str(port)})\n"
                "    procutil.assert_loopback_only(h)\n")
    wildcard = unpinned.replace("{'PORT': str(port)}", "{'PORT': str(port), 'HOST': '0.0.0.0'}")
    pinned = unpinned.replace("{'PORT': str(port)}", "{'PORT': str(port), 'HOST': '127.0.0.1'}")
    unchecked = pinned.replace("    procutil.assert_loopback_only(h)\n", "")
    assert server_launch_problems(unpinned) == ["<mem>:3 start_server_on_free_port"]
    assert server_launch_problems(wildcard) == ["<mem>:3 start_server_on_free_port"]
    assert server_launch_problems(pinned) == []
    assert boot_check_problems(pinned) == []
    assert boot_check_problems(unchecked) == ["<mem>:3 start_server_on_free_port"]


@pytest.mark.parametrize("src", [
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    s = procutil.start_server(['php', '-S', f'127.0.0.1:{port}'])\n"
    "    return s\n",
    "from fuzzlab import procutil\n"
    "def boot(port):\n"
    "    procutil.assert_loopback_only(None)\n"
    "    s = procutil.start_server(['php', '-S', f'127.0.0.1:{port}'])\n"  # check before the boot
    "    return s\n",
    "from fuzzlab import procutil as pu\n"
    "def boot(port):\n"
    "    s = pu.start_server(['php', '-S', f'127.0.0.1:{port}'])\n"
    "    other.assert_loopback_only(s)\n"  # not procutil's
    "    return s\n",
])
def test_the_boot_check_rule_flags_synthetic_offenders(src):
    assert boot_check_problems(src), src


@pytest.mark.parametrize("src", [
    "from fuzzlab import procutil as pu\n"
    "def boot(port):\n"
    "    s = pu.start_server(['php', '-S', f'127.0.0.1:{port}'])\n"
    "    wait(port)\n"
    "    pu.assert_loopback_only(s)\n"
    "    return s\n",
    "from fuzzlab import procutil\n"
    "class H:\n"
    "    def __init__(self, port):\n"
    "        self._s = procutil.start_server(['php', '-S', f'127.0.0.1:{port}'])\n"
    "        fuzzlab.procutil.assert_loopback_only(self._s)\n",
])
def test_the_boot_check_rule_passes_checked_sites(src):
    assert boot_check_problems(src) == [], src


# --- BUG-0130 follow-up: a deliberate wildcard bind in tests/ only inside a private netns --

_WILDCARD_HOSTS = {"0.0.0.0", "::", "[::]"}
_WILDCARD_TEXT = re.compile(r"0\.0\.0\.0|['\"]::['\"]|\[::\]")
#: In-process listener calls whose host argument is the bind address.
_INPROC_LISTENERS = {"bind", "HTTPServer", "ThreadingHTTPServer", "TCPServer", "create_server",
                     "start_server"}


def _is_launch(call: ast.Call, local_defs: set[str], aliases) -> bool:
    """A call that starts a process: a procutil launcher (alias-proof), ``x.launch(...)``
    (the web runner), or ``subprocess.Popen`` / ``subprocess.run``."""
    if launch_name(call, local_defs, aliases):
        return True
    f = call.func
    if isinstance(f, ast.Attribute):
        if f.attr == "launch":
            return True
        if f.attr in ("Popen", "run") and getattr(f.value, "id", "") == "subprocess":
            return True
    return False


def _netns_wrapped(argv: ast.AST | None) -> bool:
    """``private_netns([...])`` or a literal ``["unshare", ...]`` argv."""
    if isinstance(argv, ast.Call) and _callee(argv) == "private_netns":
        return True
    return (isinstance(argv, ast.List) and bool(argv.elts) and isinstance(argv.elts[0], ast.Constant)
            and argv.elts[0].value == "unshare")


def _argv_of(call: ast.Call) -> ast.AST | None:
    if call.args:
        return call.args[0]
    for k in call.keywords:
        if k.arg in ("argv", "args"):
            return k.value
    return None


def _host_constants(call: ast.Call) -> list[str]:
    out = []
    for a in call.args[:2]:
        if isinstance(a, ast.Tuple) and a.elts and isinstance(a.elts[0], ast.Constant):
            out.append(a.elts[0].value)
        elif isinstance(a, ast.Constant) and isinstance(a.value, str):
            out.append(a.value)
    out += [k.value.value for k in call.keywords
            if k.arg == "host" and isinstance(k.value, ast.Constant)]
    return out


def wildcard_bind_problems(source: str, filename: str = "<mem>") -> list[str]:
    """A test may bind a wildcard address (``0.0.0.0``, ``::``) only inside a process
    launched in a private network namespace (``tests/_netns.private_netns``):
    (1) never in-process; (2) a launch whose argv (or a name it uses, assigned in the
    enclosing function or at module level) carries wildcard text is netns-wrapped;
    (3) a call that passes a wildcard literal to a same-module function reaches only
    netns-wrapped launches there."""
    tree = ast.parse(source)
    parents = _parents(tree)
    local_defs = _defines(tree)
    aliases = procutil_aliases(tree)
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    module_assigns = [n for n in tree.body if isinstance(n, ast.Assign)]

    def enclosing(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    def strings_for(expr, scope):
        out = [x.value for x in ast.walk(expr) if isinstance(x, ast.Constant) and isinstance(x.value, str)]
        names = {x.id for x in ast.walk(expr) if isinstance(x, ast.Name)}
        pools = list(module_assigns) + ([n for n in ast.walk(scope) if isinstance(n, ast.Assign)]
                                        if scope is not None else [])
        for a in pools:
            if any(isinstance(t, ast.Name) and t.id in names for t in a.targets):
                out += [x.value for x in ast.walk(a.value)
                        if isinstance(x, ast.Constant) and isinstance(x.value, str)]
        return out

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _callee(node)
        if _is_launch(node, local_defs, aliases):
            argv = _argv_of(node)
            if argv is not None and not _netns_wrapped(argv):
                exprs = [argv] + [k.value for k in node.keywords if k.arg == "env"]
                texts = [t for e in exprs for t in strings_for(e, enclosing(node))]
                if any(_WILDCARD_TEXT.search(t) or t in _WILDCARD_HOSTS for t in texts):
                    out.append(f"{filename}:{node.lineno} wildcard launch outside a private netns")
            continue
        if name in _INPROC_LISTENERS and any(h in _WILDCARD_HOSTS for h in _host_constants(node)):
            out.append(f"{filename}:{node.lineno} in-process wildcard {name}")
            continue
        if isinstance(node.func, ast.Name) and node.func.id in funcs and any(
                isinstance(a, ast.Constant) and a.value in _WILDCARD_HOSTS for a in node.args):
            target = [c for c in ast.walk(funcs[node.func.id])
                      if isinstance(c, ast.Call) and _is_launch(c, local_defs, aliases)]
            if not target or not all(_netns_wrapped(_argv_of(c)) for c in target):
                out.append(f"{filename}:{node.lineno} wildcard passed to {node.func.id}, "
                           "which does not launch in a private netns")
    return out


def test_no_test_binds_a_wildcard_address_outside_a_private_netns():
    problems = []
    for path in sorted((REPO / "tests").rglob("*.py")):
        problems += wildcard_bind_problems(path.read_text(encoding="utf-8"),
                                           path.relative_to(REPO).as_posix())
    assert problems == [], ("a deliberate wildcard bind must run under tests/_netns.private_netns "
                            "(BUG-0130):\n" + "\n".join(problems))


@pytest.mark.parametrize("src", [
    "import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 0))\n",
    "from http.server import HTTPServer\nHTTPServer(('::', 0), object)\n",
    "import sys\nfrom fuzzlab import procutil\n"
    "procutil.start_server([sys.executable, '-c', \"s.bind(('0.0.0.0', 0))\"])\n",
    "import sys\nfrom fuzzlab import procutil as pu\n"
    "PROG = \"s.bind(('0.0.0.0', 0))\"\n"
    "def boot():\n    return pu.start_server([sys.executable, '-c', PROG])\n",
    "import sys\nfrom fuzzlab import procutil\n"
    "def srv(host):\n    return procutil.start_server([sys.executable, '-c', 'P', host])\n"
    "def test_x():\n    srv('0.0.0.0')\n",
    "import sys\n"
    "async def go(r):\n"
    "    prog = \"s.bind(('0.0.0.0', 0))\"\n"
    "    await r.launch([sys.executable, '-c', prog])\n",
    "import subprocess, sys\n"
    "subprocess.Popen([sys.executable, '-c', \"s.bind(('0.0.0.0', 0))\"])\n",
])
def test_the_netns_rule_flags_synthetic_offenders(src):
    assert wildcard_bind_problems(src), src


@pytest.mark.parametrize("src", [
    "import sys\nfrom fuzzlab import procutil\nfrom tests._netns import private_netns\n"
    "procutil.start_server(private_netns([sys.executable, '-c', \"s.bind(('0.0.0.0', 0))\"]))\n",
    "import sys\nfrom fuzzlab import procutil\nfrom tests._netns import private_netns\n"
    "def srv(host):\n    return procutil.start_server(private_netns([sys.executable, '-c', 'P', host]))\n"
    "def test_x():\n    srv('0.0.0.0')\n",
    "import sys\nfrom fuzzlab import procutil\n"
    "procutil.start_server(['unshare', '-rn', sys.executable, '-c', \"s.bind(('0.0.0.0', 0))\"])\n",
    "import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 0))\n",
    # refusing a wildcard is not binding one (the proxy refusal tests)
    "import asyncio\nsrv = Server(host='0.0.0.0')\nasyncio.run(srv.start())\n",
])
def test_the_netns_rule_passes_namespaced_or_loopback_binds(src):
    assert wildcard_bind_problems(src) == [], src
