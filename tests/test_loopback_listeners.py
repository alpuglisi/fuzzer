"""Every listener binds loopback only, through one gate (BUG-0080, D11, FR-CORE-25,
PA-0081).

`fuzzlab proxy --host 0.0.0.0` bound every interface: the web panel and the OOB
listener each had their own loopback check, and the proxy CLI had none.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from fuzzlab.core.net import is_loopback_host, require_loopback

PKG = Path(__file__).resolve().parent.parent / "fuzzlab"
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


def _is_listener(node: ast.Call) -> bool:
    name = _callee(node)
    if name == "run":                               # only uvicorn.run
        return isinstance(node.func, ast.Attribute) and \
            getattr(node.func.value, "id", "") == "uvicorn"
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
    out = []
    parents: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[c] = p
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_listener(node)):
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


def test_the_guard_flags_an_ungated_listener():
    offender = ("import asyncio\n"
                "async def serve(host):\n"
                "    await asyncio.start_server(lambda r, w: None, host, 8080)\n")
    assert listener_problems(offender) == ["<mem>:3 start_server"]
    gated = ("import asyncio\nfrom fuzzlab.core.net import require_loopback\n"
             "async def serve(host):\n    require_loopback(host)\n"
             "    await asyncio.start_server(lambda r, w: None, host, 8080)\n")
    assert listener_problems(gated) == []
