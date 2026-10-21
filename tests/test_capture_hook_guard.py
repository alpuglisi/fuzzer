"""Whole-package guard for BUG-0548 / PA-0548: a proxy addon's per-flow hooks take the
exchange and return; the work is done off the proxy's event loop.

mitmproxy runs an addon's hooks on the one loop that carries every proxied request, so
anything a hook does stalls every browser request (audit defect 22: the capture
recorder decoded, redacted and built each record there, ~7 ms a 64 KiB JSON response,
~100 ms a 1 MiB one, measured). For every module of ``fuzzlab/`` that defines mitmproxy's
module-level ``addons``, every per-flow hook of its classes -- with every method it
reaches through ``self.<name>(...)`` and every function of the package it reaches by
name -- must not:

* call body or record work: decoding (``get_content``, ``get_text``, ``decode_body``,
  ``read_body``), redaction (``redact_*``), building or serialising a record
  (``make_record``, ``build_record``, ``to_json``, ``json.dump(s)`` / ``loads``) or
  writing it (``append_record``);
* read a flow message's decoded body (``.content`` / ``.text`` of a request or a
  response: mitmproxy decodes it per ``Content-Encoding`` on access).

A writer thread's target (``threading.Thread(target=self._drain)``) is an attribute, not
a call, so the writer's own work is not reached. Proven on synthetic offenders
(PA-0034(2)), the pre-fix recorder's shape among them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.package_guard

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "fuzzlab"

#: mitmproxy's per-flow and per-connection events (not the lifecycle: load, configure,
#: running, done, update).
FLOW_HOOKS = frozenset({
    "requestheaders", "request", "responseheaders", "response", "error", "http_connect",
    "http_connect_upstream", "http_connected", "http_connect_error", "websocket_start",
    "websocket_message", "websocket_end", "tcp_start", "tcp_message", "tcp_end",
    "tcp_error", "udp_start", "udp_message", "udp_end", "udp_error", "dns_request",
    "dns_response", "dns_error", "client_connected", "client_disconnected",
    "server_connect", "server_connected", "server_disconnected", "server_connect_error",
    "tls_clienthello", "tls_start_client", "tls_start_server", "tls_established_client",
    "tls_established_server", "tls_failed_client", "tls_failed_server",
    "quic_start_client", "quic_start_server"})
#: Calls that do a body's or a record's work.
WORK_CALLS = frozenset({
    "get_content", "get_text", "decode_body", "read_body", "redact_body", "redact_headers",
    "redact_url", "redact_json_body", "redact_form_body", "redact_multipart_body",
    "make_record", "build_record", "to_json", "dumps", "dump", "loads", "append_record"})
#: A flow message's decoded body, read as an attribute.
BODY_ATTRS = frozenset({"content", "text"})
MESSAGES = frozenset({"request", "response", "req", "res"})

_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _is_addon_module(tree: ast.Module) -> bool:
    return any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "addons"
                                                 for t in n.targets) for n in tree.body)


def _module_path(module: str) -> Path | None:
    if not module.startswith("fuzzlab"):
        return None
    base = ROOT.joinpath(*module.split("."))
    for cand in (base.with_suffix(".py"), base / "__init__.py"):
        if cand.exists():
            return cand
    return None


class _Resolver:
    """Top-level functions by name: the module's own, and those it imports by name from
    a ``fuzzlab`` module (followed into that module)."""

    def __init__(self, sources: dict[str, str] | None = None):
        self._trees: dict[str, ast.Module] = {}
        self._sources = sources or {}

    def tree(self, key: str) -> ast.Module | None:
        if key not in self._trees:
            if key in self._sources:
                self._trees[key] = ast.parse(self._sources[key])
            else:
                path = _module_path(key)
                if path is None:
                    return None
                self._trees[key] = ast.parse(path.read_text())
        return self._trees[key]

    def function(self, key: str, name: str):
        tree = self.tree(key)
        if tree is None:
            return None
        for node in tree.body:
            if isinstance(node, _FUNCS) and node.name == name:
                return key, node
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    if (alias.asname or alias.name) == name:
                        return self.function(node.module, alias.name)
        return None


def _offences(fn) -> list[str]:
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name in WORK_CALLS:
                found.append(f"calls {name}")
        elif isinstance(node, ast.Attribute) and node.attr in BODY_ATTRS and \
                isinstance(node.ctx, ast.Load):
            v = node.value
            owner = v.id if isinstance(v, ast.Name) else (
                v.attr if isinstance(v, ast.Attribute) else "")
            if owner in MESSAGES:
                found.append(f"reads {owner}.{node.attr}")
    return found


def _reached(fn, methods: dict, key: str, resolver: _Resolver):
    """``fn`` and what it reaches: ``self.<m>(...)`` methods and functions by name."""
    seen, todo, out = set(), [(key, fn)], []
    while todo:
        k, f = todo.pop()
        if (k, f.name, id(f)) in seen:
            continue
        seen.add((k, f.name, id(f)))
        out.append((k, f))
        for node in ast.walk(f):
            if not isinstance(node, ast.Call):
                continue
            c = node.func
            if isinstance(c, ast.Attribute) and isinstance(c.value, ast.Name) and \
                    c.value.id == "self" and c.attr in methods and k == key:
                todo.append((k, methods[c.attr]))
            elif isinstance(c, ast.Name):
                hit = resolver.function(k, c.id)
                if hit is not None:
                    todo.append(hit)
    return out


def hook_work(key: str, resolver: _Resolver) -> list[str]:
    """``Class.hook -> function: offence`` for every per-flow hook of an addon module."""
    tree = resolver.tree(key)
    found = []
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        methods = {f.name: f for f in cls.body if isinstance(f, _FUNCS)}
        for hook in sorted(set(methods) & FLOW_HOOKS):
            for k, f in _reached(methods[hook], methods, key, resolver):
                found += [f"{cls.name}.{hook} -> {k}:{f.name}: {o}" for o in _offences(f)]
    return found


def _addon_modules() -> list[str]:
    keys = []
    for path in sorted(PKG.rglob("*.py")):
        if _is_addon_module(ast.parse(path.read_text())):
            keys.append(".".join(path.relative_to(ROOT).with_suffix("").parts))
    return keys


def test_no_proxy_hook_does_body_or_record_work_on_the_loop():
    keys = _addon_modules()
    assert "fuzzlab.disco.recorder" in keys          # the guard sees the capture proxy
    resolver = _Resolver()
    assert {k: hook_work(k, resolver) for k in keys} == {k: [] for k in keys}


_PRE_FIX = '''
from fuzzlab.disco.capture import make_record
class Recorder:
    def response(self, flow):
        req, res = flow.request, flow.response
        self._enqueue(make_record(kind="http", req_body=req.get_content(strict=False),
                                  res_body=res.get_content(strict=False)))
    def _enqueue(self, item):
        self._queue.put_nowait(item)
addons = [Recorder()]
'''

_HELPER = '''
import json
class A:
    def response(self, flow):
        self.q.put(self._take(flow))
    def _take(self, flow):
        return _serialise(flow.response.content)
def _serialise(body):
    return json.dumps({"b": body.decode()})
addons = [A()]
'''

_CLEAN = '''
import threading
class A:
    def __init__(self):
        self.w = threading.Thread(target=self._drain)
    def response(self, flow):
        self.q.put((flow.request.raw_content, flow.response.raw_content))
    def websocket_message(self, flow):
        self.q.put(flow.websocket.messages[-1].content)
    def _drain(self):
        make_record(redact_body(self.q.get()))
    def done(self):
        json.dump({}, open("s", "w"))
addons = [A()]
'''


def test_the_hook_guard_catches_synthetic_offenders():
    resolver = _Resolver({"pre_fix": _PRE_FIX, "helper": _HELPER, "clean": _CLEAN})
    pre = hook_work("pre_fix", resolver)
    assert "Recorder.response -> pre_fix:response: calls make_record" in pre
    assert "Recorder.response -> pre_fix:response: calls get_content" in pre
    helper = hook_work("helper", resolver)
    assert "A.response -> helper:_take: reads response.content" in helper
    assert "A.response -> helper:_serialise: calls dumps" in helper
    assert hook_work("clean", resolver) == []
    # an imported fuzzlab function is followed into its module
    via = _Resolver({"via": "from fuzzlab.disco.capture import build_record\n"
                            "class A:\n    def error(self, flow):\n"
                            "        self.q.put(build_record(flow))\naddons = [A()]\n"})
    via_work = hook_work("via", via)
    assert via_work[0] == "A.error -> via:error: calls build_record"
    assert "A.error -> fuzzlab.disco.capture:build_record: calls decode_body" in via_work
