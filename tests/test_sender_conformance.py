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
    prg_capable = True                               # FR-FUZZ-49

    def __init__(self):
        self.calls = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        self.calls.append(dict(url=url, param=param, value=value, timing=timing,
                               method=method, location=location,
                               content_type=content_type, entries=entries, prg=prg))
        return Probe(200, "ok", headers={})


def _wrap(cls, inner):
    """Build a wrapper around ``inner``. `_FormBoundSender` also takes its candidate
    (a form point on another URL, so this send passes through unbound); `_PrgRun` its
    run's counters (FR-FUZZ-49)."""
    if cls.__name__ == "_FormBoundSender":
        from fuzzlab.oracle.probe import Candidate
        return cls(inner, Candidate(url="http://other/f", param="p",
                                    base_entries=(("p", ""),)))
    if cls.__name__ == "_PrgRun":
        from fuzzlab.oracle.oracle import PRG_COUNTERS
        return cls(inner, dict.fromkeys(PRG_COUNTERS, 0))
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
                      entries=[("body", "{}"), ("form", "submit")]),
                 # the strategy run's PRG property (FR-FUZZ-49, P8)
                 dict(method="POST", location="body", entries=[("body", "{}")],
                      prg=True),
                 dict(method="POST", location="body", content_type="application/json",
                      prg=True)):
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


def prg_capability_problems(cls) -> list[str]:
    """A wrapper reports its inner sender's PRG capability (FR-FUZZ-49): the oracle asks
    for PRG observation only from a sender that can make it."""
    from fuzzlab.oracle.probe import accepts_prg
    out = []
    capable, plain = _Recorder(), _Recorder()
    plain.prg_capable = False
    if not accepts_prg(_wrap(cls, capable)):
        out.append("hides a capable inner sender's prg_capable")
    if accepts_prg(_wrap(cls, plain)):
        out.append("claims prg_capable over an incapable inner sender")
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
            ("fuzzlab.harness.auto", "_CountingSender"),
            ("fuzzlab.harness.auto", "_FragmentGuard"),               # forms phase 3
            ("fuzzlab.oracle.oracle", "_FormBoundSender"),
            ("fuzzlab.oracle.oracle", "_PrgRun"),                     # FR-FUZZ-49
            ("fuzzlab.oracle.oracle", "_SessionNotes")} <= wrappers   # FR-SESS-20


def test_every_seam_class_accepts_the_full_protocol_signature():
    problems = {f"{m}.{c}": signature_problems(_load(m, c))
                for m, c, _w in _seam_classes()}
    assert {k: v for k, v in problems.items() if v} == {}


def test_every_wrapper_forwards_every_protocol_argument():
    problems = {f"{m}.{c}": forwarding_problems(_load(m, c))
                for m, c, w in _seam_classes() if w}
    assert problems and {k: v for k, v in problems.items() if v} == {}


def test_every_wrapper_reports_its_inner_senders_prg_capability():
    problems = {f"{m}.{c}": prg_capability_problems(_load(m, c))
                for m, c, w in _seam_classes() if w}
    assert problems and {k: v for k, v in problems.items() if v} == {}


def test_every_concrete_sender_declares_prg_capable():
    concrete = {(m, c) for m, c, w in _seam_classes()
                if not w and (m, c) != ("fuzzlab.oracle.probe", "Sender")}
    assert concrete and all(_load(m, c).prg_capable is True for m, c in concrete)


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
                                                   "missing parameter 'entries'",
                                                   "missing parameter 'prg'"]
    assert forwarding_problems(_OldCostCounter)[0].startswith("rejects a protocol argument")
    assert signature_problems(_Dropper) == ["missing parameter 'entries'",
                                            "missing parameter 'prg'"]
    assert forwarding_problems(_Dropper)[0] == (
        "content_type: sent 'application/json', inner got None")


class _PrgDropper:
    """Accepts the whole protocol (FR-FUZZ-49) but drops ``prg``, and does not report
    its inner sender's capability."""

    def __init__(self, inner):
        self._inner = inner

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        return self._inner.send(url, param, value, timing=timing, method=method,
                                location=location, content_type=content_type,
                                entries=entries)


def test_the_guards_catch_a_dropped_prg_property():
    assert signature_problems(_PrgDropper) == []
    assert "prg: sent True, inner got False" in forwarding_problems(_PrgDropper)
    assert prg_capability_problems(_PrgDropper) == [
        "hides a capable inner sender's prg_capable"]


# --- placement: a payload lands exactly where the point says (BUG-0115, PA-0115) ------
import pytest                                               # noqa: E402

from fuzzlab.oracle.probe import UnplaceableLocation        # noqa: E402


class _Wire:
    """What reached the wire, in one shape for every sender."""

    def __init__(self):
        self.sent = []

    # requests-style session (RequestsProbeSender, RequestsCorrelatingSender)
    cookies: dict = {}

    @staticmethod
    def _json(headers, raw):
        """A JSON body's object (forms phase 3), or {} when the send is not JSON."""
        import json
        if (headers or {}).get("Content-Type") != "application/json":
            return {}
        return json.loads(raw)

    def request(self, method, url, **kw):
        from urllib.parse import parse_qsl, urlsplit
        query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        params = kw.get("params")
        query.update(dict(params) if isinstance(params, (dict, list)) else {})
        data = kw.get("data")
        body = dict(data) if isinstance(data, (dict, list)) else {}
        headers = dict(kw.get("headers") or {})
        self.sent.append({"query": query, "body": body, "headers": headers,
                          "json": self._json(headers, data)})

        class R:
            status_code, text, headers = 200, "ok", {}
        return R()

    # core seam transport (SeamProbeSender)
    def transport(self, method, url, headers, body, timeout):
        from urllib.parse import parse_qsl, urlsplit
        json_body = self._json(headers, body)
        self.sent.append({"query": dict(parse_qsl(urlsplit(url).query)),
                          "body": {} if json_body else dict(parse_qsl((body or b"").decode())),
                          "headers": dict(headers), "json": json_body})
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


#: Every location a probe sender must place (forms phase 3 added ``json``, FR-CORE-36).
PLACEABLE = ("query", "body", "header", "json")


def placement_problems(send, locations=PLACEABLE) -> list[str]:
    """Send a marked value at each placeable location; it must arrive there only."""
    out = []
    for location in locations:
        wire = _Wire()
        try:
            send(wire, location)
        except Exception as exc:                          # noqa: BLE001 (reported)
            out.append(f"{location}: raised {exc!r}")
            continue
        got = wire.sent[-1]
        where = [k for k in ("query", "body", "headers", "json")
                 if got.get(k, {}).get("X-Probe") == "zqmark"]
        if where != [{"header": "headers"}.get(location, location)]:
            out.append(f"{location}: landed in {where}")
    return out


def _via(factory):
    def send(wire, location):
        factory(wire).send("http://h/a.php", "X-Probe", "zqmark",
                           method="POST" if location in ("body", "json") else "GET",
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
    assert placement_problems(send, ("query", "body", "header")) == []
    # greybox does not rebuild JSON bodies: it refuses (FR-FUZZ-47), never relocates
    for location in ("fragment", "json"):
        wire = _Wire()
        with pytest.raises(UnplaceableLocation):
            send(wire, location)
        assert wire.sent == []


def test_the_placement_check_catches_a_relocating_sender():
    class Relocating:                           # BUG-0115's shape: header -> query
        def __init__(self, wire):
            self._wire = wire

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None):
            key = "data" if location == "body" else "params"
            return self._wire.request(method, url, **{key: {param: value}})
    assert placement_problems(_via(Relocating)) == ["header: landed in ['query']",
                                                    "json: landed in ['query']"]

    class FormEncodesJson(Relocating):          # json sent as a form field
        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None):
            if location == "json":
                return self._wire.request(method, url, data={param: value})
            return super().send(url, param, value, method=method, location=location)
    assert "json: landed in ['body']" in placement_problems(_via(FormEncodesJson))


# --- json (forms phase 3, FR-CORE-36 / FR-FUZZ-47): one leaf of the whole body ----------
_JSON_ENTRIES = ((("a", "b", 0), "x"), (("a", "b", 1), "old"), (("n",), 5),
                 (("t",), True), (("z",), None), (("e",), []))
_JSON_WANT = {"a": {"b": ["x", "zqmark"]}, "n": 5, "t": True, "z": None, "e": []}


def json_placement_problems(send) -> list[str]:
    """A nested leaf with typed siblings: the body is rebuilt with that leaf (only) set
    to the payload as a string, sent as application/json, nothing in the query; a
    malformed leaf name is refused with nothing sent."""
    wire = _Wire()
    send(wire, "a.b[1]", _JSON_ENTRIES)
    got = wire.sent[-1]
    out = []
    if got["json"] != _JSON_WANT:
        out.append(f"body {got['json']!r}")
    if got["headers"].get("Content-Type") != "application/json":
        out.append(f"content type {got['headers'].get('Content-Type')!r}")
    if got["query"] or got["body"]:
        out.append(f"also sent query {got['query']!r} / form {got['body']!r}")
    wire = _Wire()
    try:
        send(wire, "a.b[", _JSON_ENTRIES)
        out.append("a malformed leaf name was sent")
    except UnplaceableLocation:
        if wire.sent:
            out.append("a malformed leaf name was refused after a send")
    return out


@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_every_sender_places_a_json_leaf_in_the_rebuilt_body(key):
    def send(wire, name, entries):
        PLACEMENT_FACTORIES[key](wire).send("http://h/api", name, "zqmark", method="POST",
                                            location="json", entries=entries)
    assert json_placement_problems(send) == []


@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_a_raw_body_send_at_a_json_point_is_refused_not_reinterpreted(key):
    """An XXE / upload strategy sends a raw whole body (``content_type``): a JSON leaf
    cannot carry it, so the sender refuses before sending anything (PA-0115)."""
    wire = _Wire()
    with pytest.raises(UnplaceableLocation):
        PLACEMENT_FACTORIES[key](wire).send("http://h/api", "a", "<x/>", method="POST",
                                            location="json",
                                            content_type="application/xml")
    assert wire.sent == []


def test_the_form_bound_sender_places_a_json_leaf_in_the_rebuilt_body():
    from fuzzlab.oracle.oracle import _FormBoundSender
    from fuzzlab.oracle.probe import Candidate

    def send(wire, name, entries):
        cand = Candidate(url="http://h/api", param=name, method="POST", location="json",
                         base_entries=tuple((list(p), v) for p, v in entries))
        _FormBoundSender(_requests_factory(wire), cand).send(
            "http://h/api", name, "zqmark", method="POST", location="json")
    assert json_placement_problems(send) == []


def test_the_json_check_catches_a_sender_that_drops_siblings_or_types():
    class Flat:                                 # {param: value}, siblings dropped
        def __init__(self, wire):
            self._wire = wire

        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None):
            import json
            return self._wire.request(method, url, data=json.dumps({param: value}),
                                      headers={"Content-Type": "application/json"})

    def send(wire, name, entries):
        Flat(wire).send("http://h/api", name, "zqmark", method="POST", location="json",
                        entries=entries)
    problems = json_placement_problems(send)
    assert problems[0].startswith("body {'a.b[1]': 'zqmark'}")
    assert problems[-1] == "a malformed leaf name was sent"


# --- the M6 executor places a fragment inside an SPA hash route (forms phase 3) ---------
def test_the_executor_places_a_fragment_point_inside_the_hash_route(monkeypatch):
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    from tests.test_json_points import _fake_playwright
    gotos = _fake_playwright(monkeypatch)
    for url, want in (("http://h/#/search", "http://h/#/search?q=zqmark"),
                      ("http://h/#!/s?page=2", "http://h/#!/s?page=2&q=zqmark"),
                      ("http://h/p.php", "http://h/p.php#q=zqmark")):
        gotos.clear()
        PlaywrightBrowserExecutor().run(ExecRequest(url=url, param="q", value="zqmark",
                                                    location="fragment"), "t")
        assert gotos == [want] and want.count("#") == 1
    for location in ("json", "body", "header"):              # refused before any browser
        gotos.clear()
        obs = PlaywrightBrowserExecutor().run(ExecRequest(
            url="http://h/#/search", param="q", value="zqmark", location=location), "t")
        assert not obs.executed and gotos == []


@pytest.mark.xfail(strict=True, reason="BUG-0115 instance 4, pinned not fixed: the probe "
                   "senders' last branch still sends an unknown location (e.g. fragment) "
                   "as query. Fixing it can move scored ground-truth results and needs a "
                   "live scored multitarget run (PA-0042/0047); flagged to the orchestrator")
@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_senders_refuse_an_unplaceable_location(key):
    with pytest.raises(UnplaceableLocation):
        PLACEMENT_FACTORIES[key](_Wire()).send("http://h/a.php", "p", "v",
                                               location="fragment")


# --- FR-FUZZ-49: a probe asking for PRG observation is placed exactly as any other ------
def _via_prg(factory):
    def send(wire, location):
        factory(wire).send("http://h/a.php", "X-Probe", "zqmark",
                           method="POST" if location in ("body", "json") else "GET",
                           location=location, prg=True)
    return send


@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_every_sender_places_a_prg_probe_where_the_point_says(key):
    assert placement_problems(_via_prg(PLACEMENT_FACTORIES[key])) == []


class _PrgWire(_Wire):
    """A POST is answered ``303 Location: /show``; any GET with a page."""

    def _answer(self, method, url):
        self.sent[-1].update(method=method, url=url)
        if method == "POST":
            return 303, {"Location": "/show"}, b""
        return 200, {"Content-Type": "text/html"}, b"shown"

    def request(self, method, url, **kw):
        super().request(method, url, **kw)
        status, headers, body = self._answer(method, url)

        class R:
            status_code, text = status, body.decode()
        R.headers = headers
        return R()

    def transport(self, method, url, headers, body, timeout):
        super().transport(method, url, headers, body, timeout)
        return self._answer(method, url)


@pytest.mark.parametrize("key", sorted(PLACEMENT_FACTORIES))
def test_every_sender_that_declares_prg_makes_the_follow_up(key):
    """PA-0035: the declared capability is checked on the sender's real send path: a
    plain GET of the redirect target, no payload, attached as ``probe.followed``."""
    wire = _PrgWire()
    sender = PLACEMENT_FACTORIES[key](wire)
    assert sender.prg_capable is True
    probe = sender.send("http://h/a.php", "p", "zqmark", method="POST", location="body",
                        prg=True)
    assert probe.status == 303 and probe.followed is not None
    assert probe.followed.text == "shown" and probe.followed.url == "http://h/show"
    assert [(s["method"], s["url"]) for s in wire.sent] == [("POST", "http://h/a.php"),
                                                            ("GET", "http://h/show")]
    assert wire.sent[1]["query"] == {} and wire.sent[1]["body"] == {}
    wire = _PrgWire()
    PLACEMENT_FACTORIES[key](wire).send("http://h/a.php", "p", "zqmark", method="POST",
                                        location="body")
    assert len(wire.sent) == 1                        # not asked: never follows
