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
             content_type=None, entries=None):
        self.calls.append(dict(url=url, param=param, value=value, timing=timing,
                               method=method, location=location,
                               content_type=content_type, entries=entries))
        return Probe(200, "ok", headers={})


def _wrap(cls, inner):
    """Build a wrapper around ``inner``. `_FormBoundSender` also takes its candidate
    (a form point on another URL, so this send passes through unbound)."""
    if cls.__name__ == "_FormBoundSender":
        from fuzzlab.oracle.probe import Candidate
        return cls(inner, Candidate(url="http://other/f", param="p",
                                    base_entries=(("p", ""),)))
    return cls(inner)


def forwarding_problems(cls) -> list[str]:
    """Call the wrapper with every non-default protocol argument; each must reach the
    inner sender unchanged."""
    out = []
    # a raw-body send carries content_type; a form send carries its entry list (forms
    # phase 1): each protocol argument must reach the inner sender unchanged
    for sent in (dict(timing=True, method="POST", location="body",
                      content_type="application/json"),
                 dict(timing=True, method="POST", location="body",
                      entries=[("body", "{}"), ("form", "submit")])):
        inner = _Recorder()
        try:
            _wrap(cls, inner).send("http://h/x", "body", "{}", **sent)
        except TypeError as exc:
            return out + [f"rejects a protocol argument: {exc}"]
        if len(inner.calls) != 1:
            return [f"made {len(inner.calls)} inner sends, expected 1"]
        got = inner.calls[0]
        out += [f"{k}: sent {v!r}, inner got {got[k]!r}" for k, v in sent.items()
                if got[k] != v]
    return out


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
    assert signature_problems(_OldCostCounter) == ["missing parameter 'content_type'",
                                                   "missing parameter 'entries'"]
    assert forwarding_problems(_OldCostCounter)[0].startswith("rejects a protocol argument")
    assert signature_problems(_Dropper) == ["missing parameter 'entries'"]
    assert forwarding_problems(_Dropper)[0] == (
        "content_type: sent 'application/json', inner got None")


# --- placement: a payload lands exactly where the point says (BUG-0115, PA-0115) ------
import pytest                                               # noqa: E402

from fuzzlab.oracle.probe import UnplaceableLocation        # noqa: E402


class _Wire:
    """What reached the wire, in one shape for every sender."""

    def __init__(self):
        self.sent = []

    # requests-style session (RequestsProbeSender, RequestsCorrelatingSender)
    cookies: dict = {}

    def request(self, method, url, **kw):
        from urllib.parse import parse_qsl, urlsplit
        query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        params = kw.get("params")
        query.update(dict(params) if isinstance(params, (dict, list)) else {})
        data = kw.get("data")
        body = dict(data) if isinstance(data, (dict, list)) else {}
        self.sent.append({"query": query, "body": body, "headers": dict(kw.get("headers")
                                                                        or {})})

        class R:
            status_code, text, headers = 200, "ok", {}
        return R()

    # core seam transport (SeamProbeSender)
    def transport(self, method, url, headers, body, timeout):
        from urllib.parse import parse_qsl, urlsplit
        self.sent.append({"query": dict(parse_qsl(urlsplit(url).query)),
                          "body": dict(parse_qsl((body or b"").decode())),
                          "headers": dict(headers)})
        return 200, {}, b"ok"


def _seam_factory(wire):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.probesender import SeamProbeSender
    return SeamProbeSender(HttpClient(RequestBudget(100), ["h"], transport=wire.transport))


def _requests_factory(wire):
    from fuzzlab.tools.probesender import RequestsProbeSender
    return RequestsProbeSender(session=wire)


#: Every concrete (non-wrapper, non-abstract) seam class, with how to build it over a
#: recording wire. A new sender found by `_seam_classes` must be added here.
PLACEMENT_FACTORIES = {
    ("fuzzlab.tools.probesender", "SeamProbeSender"): _seam_factory,
    ("fuzzlab.tools.probesender", "RequestsProbeSender"): _requests_factory,
}


def placement_problems(send) -> list[str]:
    """Send a marked value at each placeable location; it must arrive there only."""
    out = []
    for location in ("query", "body", "header"):
        wire = _Wire()
        try:
            send(wire, location)
        except Exception as exc:                          # noqa: BLE001 (reported)
            out.append(f"{location}: raised {exc!r}")
            continue
        got = wire.sent[-1]
        where = [k for k in ("query", "body", "headers")
                 if got[k].get("X-Probe") == "zqmark"]
        if where != [{"header": "headers"}.get(location, location)]:
            out.append(f"{location}: landed in {where}")
    return out


def _via(factory):
    def send(wire, location):
        factory(wire).send("http://h/a.php", "X-Probe", "zqmark",
                           method="POST" if location == "body" else "GET",
                           location=location)
    return send


def test_every_concrete_sender_has_a_placement_factory():
    concrete = {(m, c) for m, c, w in _seam_classes()
                if not w and (m, c) != ("fuzzlab.oracle.probe", "Sender")}
    assert concrete == set(PLACEMENT_FACTORIES)


@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_every_sender_places_a_probe_where_the_point_says(key):
    assert placement_problems(_via(PLACEMENT_FACTORIES[key])) == []


def test_the_greybox_sender_places_a_probe_where_the_point_says():
    from fuzzlab.greybox.run import RequestsCorrelatingSender

    def send(wire, location):
        RequestsCorrelatingSender(session=wire, id_factory=lambda: "c").send_correlated(
            "http://h/a.php", "X-Probe", "zqmark", location=location)
    assert placement_problems(send) == []
    with pytest.raises(UnplaceableLocation):
        send(_Wire(), "fragment")


def test_the_placement_check_catches_a_relocating_sender():
    class Relocating:                           # BUG-0115's shape: header -> query
        def __init__(self, wire):
            self._wire = wire

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None):
            key = "data" if location == "body" else "params"
            return self._wire.request(method, url, **{key: {param: value}})
    assert placement_problems(_via(Relocating)) == ["header: landed in ['query']"]


@pytest.mark.xfail(strict=True, reason="BUG-0115 instance 4, pinned not fixed: the probe "
                   "senders' last branch still sends an unknown location (e.g. fragment) "
                   "as query. Fixing it can move scored ground-truth results and needs a "
                   "live scored multitarget run (PA-0042/0047); flagged to the orchestrator")
@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_senders_refuse_an_unplaceable_location(key):
    with pytest.raises(UnplaceableLocation):
        PLACEMENT_FACTORIES[key](_Wire()).send("http://h/a.php", "p", "v",
                                               location="fragment")
