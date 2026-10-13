"""Every implementation or wrapper of the oracle's `Sender` seam accepts its full
signature, and every wrapper forwards what it accepts (BUG-0071, PA-0072).

`_CostCounter` (the bandit's per-strategy cost wrapper) lacked `content_type` after the
protocol gained it, so `fuzzlab auto --bandit` crashed on the first JSON-body / upload /
XXE probe. These checks find the seam's implementations by shape (a class in
`fuzzlab/` whose `send` takes `(self, url, param, value, …)`), so a new one is covered
without being listed. Test doubles live under `tests/` and are not scanned.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

from fuzzlab.oracle.probe import Probe, Sender

PKG = Path(__file__).resolve().parent.parent / "fuzzlab"
_SEAM_ARGS = ["self", "url", "param", "value"]


def _seam_classes() -> list[tuple[str, str, bool]]:
    """(module, class name, is_wrapper) for every `send(self, url, param, value, …)` class
    in `fuzzlab/`. A wrapper's `send` delegates to `self._inner.send` (AST, no imports
    of unrelated modules)."""
    found = []
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for fn in node.body:
                if not (isinstance(fn, ast.FunctionDef) and fn.name == "send"):
                    continue
                if [a.arg for a in fn.args.args[:4]] != _SEAM_ARGS:
                    continue
                wrapper = any(
                    isinstance(n, ast.Attribute) and n.attr == "send"
                    and isinstance(n.value, ast.Attribute) and n.value.attr == "_inner"
                    for n in ast.walk(fn))
                module = ".".join(path.relative_to(PKG.parent).with_suffix("").parts)
                found.append((module, node.name, wrapper))
    return found


def _protocol_params() -> dict[str, object]:
    sig = inspect.signature(Sender.send)
    return {name: p.default for name, p in sig.parameters.items()}


def signature_problems(cls) -> list[str]:
    """Protocol parameters `cls.send` lacks or defaults differently."""
    have = inspect.signature(cls.send).parameters
    out = []
    for name, default in _protocol_params().items():
        if name not in have:
            out.append(f"missing parameter {name!r}")
        elif have[name].default != default:
            out.append(f"{name!r} defaults to {have[name].default!r}, protocol says "
                       f"{default!r}")
    return out


class _Recorder:
    def __init__(self):
        self.calls = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None):
        self.calls.append(dict(url=url, param=param, value=value, timing=timing,
                               method=method, location=location,
                               content_type=content_type))
        return Probe(200, "ok", headers={})


def forwarding_problems(cls) -> list[str]:
    """Call the wrapper with every non-default protocol argument; each must reach the
    inner sender unchanged."""
    inner = _Recorder()
    wrapper = cls(inner)
    sent = dict(timing=True, method="POST", location="body",
                content_type="application/json")
    try:
        wrapper.send("http://h/x", "body", "{}", **sent)
    except TypeError as exc:
        return [f"rejects a protocol argument: {exc}"]
    if len(inner.calls) != 1:
        return [f"made {len(inner.calls)} inner sends, expected 1"]
    got = inner.calls[0]
    return [f"{k}: sent {v!r}, inner got {got[k]!r}" for k, v in sent.items()
            if got[k] != v]


def _load(module, name):
    return getattr(importlib.import_module(module), name)


def test_the_scan_finds_the_known_implementations():
    names = {(m, c) for m, c, _w in _seam_classes()}
    assert {("fuzzlab.oracle.oracle", "_CostCounter"),
            ("fuzzlab.harness.auto", "_CountingSender"),
            ("fuzzlab.tools.probesender", "SeamProbeSender"),
            ("fuzzlab.tools.probesender", "RequestsProbeSender"),
            ("fuzzlab.oracle.probe", "Sender")} <= names
    wrappers = {(m, c) for m, c, w in _seam_classes() if w}
    assert {("fuzzlab.oracle.oracle", "_CostCounter"),
            ("fuzzlab.harness.auto", "_CountingSender")} <= wrappers


def test_every_seam_class_accepts_the_full_protocol_signature():
    problems = {f"{m}.{c}": signature_problems(_load(m, c))
                for m, c, _w in _seam_classes()}
    assert {k: v for k, v in problems.items() if v} == {}


def test_every_wrapper_forwards_every_protocol_argument():
    problems = {f"{m}.{c}": forwarding_problems(_load(m, c))
                for m, c, w in _seam_classes() if w}
    assert problems and {k: v for k, v in problems.items() if v} == {}


# --- the guards themselves catch the defect (PA-0034(2)) -----------------------

class _OldCostCounter:
    """`_CostCounter` as it was before BUG-0071: no `content_type`."""

    def __init__(self, inner):
        self._inner = inner

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return self._inner.send(url, param, value, timing=timing, method=method,
                                location=location)


class _Dropper:
    """Accepts `content_type` but never forwards it."""

    def __init__(self, inner):
        self._inner = inner

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None):
        return self._inner.send(url, param, value, timing=timing, method=method,
                                location=location)


def test_the_guards_catch_a_missing_or_dropped_content_type():
    assert signature_problems(_OldCostCounter) == ["missing parameter 'content_type'"]
    assert forwarding_problems(_OldCostCounter)[0].startswith("rejects a protocol argument")
    assert signature_problems(_Dropper) == []
    assert forwarding_problems(_Dropper) == [
        "content_type: sent 'application/json', inner got None"]
