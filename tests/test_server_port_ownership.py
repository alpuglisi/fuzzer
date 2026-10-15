"""A started server's boot is complete only when its own process listens (BUG-0143).

Every live-boot harness and several tests picked a free port, released it, started the
server, and waited until *something* accepted a connection on that port. Under
parallel runs another test's server could hold that port. The harness then reported a
successful boot, and the test ran against the wrong application: a connection reset
when that other server stopped, or a wrong pass or fail. ``procutil.port_owner``
checks the listener's owner through the server's own sockets.
``procutil.start_server_on_free_port`` retries a port taken before the bind. A guard
keeps every ``procutil.start_server`` call next to such a check.
"""

from __future__ import annotations

import ast
import http.server
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from fuzzlab import procutil

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.package_guard


class _Foreign:
    """Another process's server, already holding a port."""

    def __init__(self) -> None:
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b"FOREIGN"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def foreign():
    f = _Foreign()
    yield f
    f.close()


def _http_server(port: int, root: Path) -> list[str]:
    return [sys.executable, "-m", "http.server", "--bind", "127.0.0.1", "--directory", str(root),
            str(port)]


def test_a_port_held_by_another_process_is_never_taken_for_the_server(foreign, tmp_path):
    (tmp_path / "who.txt").write_text("OURS")
    h = procutil.start_server(_http_server(foreign.port, tmp_path),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with pytest.raises(procutil.PortTaken):
            procutil.wait_until_listening(h, foreign.port, timeout=10.0)
        procutil.assert_loopback_only(h)  # BUG-0130: it holds nothing beyond loopback
    finally:
        procutil.stop_server(h)


def test_a_taken_port_is_retried_and_the_server_really_answers(foreign, tmp_path, monkeypatch):
    (tmp_path / "who.txt").write_text("OURS")
    real, picks = procutil.free_port, []

    def pick():
        port = foreign.port if not picks else real()
        picks.append(port)
        return port

    monkeypatch.setattr(procutil, "free_port", pick)
    h, port = procutil.start_server_on_free_port(
        lambda p: _http_server(p, tmp_path), boot_timeout=10.0,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        procutil.assert_loopback_only(h)  # BUG-0130: checked after boot
        assert picks[0] == foreign.port and port == picks[1] != foreign.port
        assert procutil.port_owner(h, port) == "ours"
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/who.txt", timeout=5).read()
        assert body == b"OURS"
    finally:
        procutil.stop_server(h)


def test_a_server_that_exits_is_reported_not_waited_out():
    """A server that rejects its configuration at startup (here a non-numeric port)
    exits before listening: reported at once, with its output, not waited out."""
    with pytest.raises(procutil.ServerDidNotListen, match="exited") as info:
        h, _port = procutil.start_server_on_free_port(
            lambda p: [sys.executable, "-m", "http.server", "--bind", "127.0.0.1", "not-a-port"],
            boot_timeout=30.0, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procutil.assert_loopback_only(h)  # not reached: it never listens
    assert "not-a-port" in str(info.value)


def test_a_port_nothing_listens_on_is_none(tmp_path):
    h, port = procutil.start_server_on_free_port(
        lambda p: _http_server(p, tmp_path), boot_timeout=10.0,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        procutil.assert_loopback_only(h)  # BUG-0130: checked after boot
        other = procutil.free_port()
        assert other != port and procutil.port_owner(h, other) == "none"
    finally:
        procutil.stop_server(h)


@pytest.mark.slow
def test_the_go_harness_never_boots_against_another_process(foreign, monkeypatch):
    """The reproduction that found BUG-0143: the Go harness reported a successful boot
    while its URL answered another server."""
    from fuzzlab.labgen.conformance import go_live_boot as g
    if not g.go_boot_available():
        pytest.skip("go toolchain unavailable")
    from fuzzlab.labgen.emitters.go_net_http import GoEmitter
    sys.path.insert(0, str(ROOT / "tests"))
    import test_multitarget_category4 as cat4

    real, picks = g._find_free_port, []

    def pick():
        port = foreign.port if not picks else real()
        picks.append(port)
        return port

    monkeypatch.setattr(g, "_find_free_port", pick)
    with g.GoLiveBootHarness(GoEmitter(), cat4._twitch_cells()[:1]) as h:
        assert str(foreign.port) not in h.base_url and len(picks) == 2
        try:
            body = urllib.request.urlopen(h.base_url + "/", timeout=5).read()
        except urllib.error.HTTPError as exc:
            body = exc.read()
        assert b"FOREIGN" not in body


# ------------------------------------------------------------------------- guard

#: (file, function) pairs that start a server whose readiness is proven another way.
ALLOWED = {
    ("tests/test_labgen_go_live_boot.py", "*"): "the server binds port 0 itself and prints "
    "the address it got; the test connects to that address",
    ("tests/test_labgen_header_injection_circlefeed_live_boot.py", "__init__"): "waits for "
    "the responder's own READY line, printed after its bind",
}
OWNERSHIP_CALLS = {"port_owner", "wait_until_listening", "start_server_on_free_port"}
#: Picking a port for the server: the race the ownership check closes. A function that
#: starts a process without picking a port (procutil's own lifecycle tests) is out of
#: scope.
PORT_PICKS = {"_free_port", "_find_free_port", "free_port", "getsockname"}


def _calls(fn: ast.AST) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            out.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
    return out


def offenders(path: Path, rel: str) -> list[str]:
    """Functions that pick a port and ``procutil.start_server`` a server on it, but never
    check who owns the port (directly, or through a same-module function or method they
    call by name)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    found = []
    for fn in funcs.values():
        starts = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and n.func.attr == "start_server"
                  and isinstance(n.func.value, ast.Name) and n.func.value.id == "procutil"]
        if not starts or (rel, fn.name) in ALLOWED or (rel, "*") in ALLOWED:
            continue
        called = _calls(fn)
        reach = set(called)
        for name in called:
            if name in funcs:
                reach |= _calls(funcs[name])
        if reach & PORT_PICKS and not reach & OWNERSHIP_CALLS:
            found.append(f"{rel}::{fn.name}")
    return found


def _modules() -> list[tuple[Path, str]]:
    paths = sorted((ROOT / "fuzzlab").rglob("*.py")) + sorted((ROOT / "tests").glob("*.py"))
    return [(p, str(p.relative_to(ROOT))) for p in paths
            if p.name != "procutil.py" and p.name != Path(__file__).name]


def test_every_started_server_is_checked_for_owning_its_port():
    bad = [o for p, rel in _modules() for o in offenders(p, rel)]
    assert bad == [], ("a procutil.start_server boot must prove the server owns its port "
                       "(procutil.start_server_on_free_port / wait_until_listening / "
                       f"port_owner; BUG-0143): {bad}")


def test_the_guard_catches_a_bare_connect_boot(tmp_path):
    offender = tmp_path / "t.py"
    offender.write_text(
        "import socket\nfrom fuzzlab import procutil\n"
        "def boot():\n"
        "    port = _free_port()\n"
        "    h = procutil.start_server(['srv', str(port)])\n"
        "    socket.create_connection(('127.0.0.1', port)).close()\n"
        "    return h\n"
        "def no_port():\n"
        "    return procutil.start_server(['sleep', '5'])\n"
        "def good(port):\n"
        "    port = _free_port()\n"
        "    h = procutil.start_server(['srv', str(port)])\n"
        "    procutil.wait_until_listening(h, port, timeout=5)\n")
    assert offenders(offender, "t.py") == ["t.py::boot"]
