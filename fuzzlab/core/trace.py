"""The evidence model behind the data-flow and sequence diagrams (FR-CORE-505).

**Events are the source of truth.** Every producer -- discovery import, the fuzzing
pipeline, the oracle -- records what it actually saw or did as one ``trace_event`` row:
append-only, versioned (``v``), keyed per run (``UNIQUE(run_id, key)``), so a re-delivered
or replayed event is ignored rather than duplicated. Bodies are built by the producers
from already-redacted values (`core.redaction`), never from raw headers or bodies.

**The diagram model is derived.** `reduce` turns events into ``dg_entity`` (actors, the
application, origins, interfaces, external references), ``dg_flow`` (who talks to whom,
in the application view or the testing overlay) and ``dg_evidence`` (which events
support each one). It is idempotent and order-independent: first/last seen are min/max,
attributes are set unions, knowledge only ever strengthens, and observation counts are
counted from ``dg_evidence`` (one row per supporting event). `rebuild` replays a run's
events into fresh ``dg_*`` rows.

**Knowledge.** Every entity and flow carries ``observed`` (directly supported by an
event: captured traffic, a browser event, a tool exchange or explicit configuration),
``inferred`` (indirect evidence; the basis is recorded in ``attrs["basis"]``) or
``unknown``. Nothing here creates a server-side component, store or internal call: a
browser-to-server exchange establishes that interaction only.

**One writer.** `TraceRecorder` buffers events (bounded) and writes a batch -- events and
their reduction -- in one transaction, on the producer's own thread and connection
(`Store` connections are per thread). A full buffer flushes synchronously (backpressure,
counted); a batch that cannot be written is counted ``dropped`` and logged, never
silently lost. Its counters are written to ``run_metrics`` (``trace_*``) so a view can say
how complete the model is.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

#: The event body schema version (``trace_event.v``).
EVENT_VERSION = 1
#: Knowledge levels, weakest first.
KNOWLEDGE = ("unknown", "inferred", "observed")
#: Values kept per attribute set: the smallest, in a fixed order, so the kept set does
#: not depend on event order; ``"<key>_more": true`` says there were more.
MAX_ATTR_VALUES = 40
#: How often a live recorder rewrites its counters to ``run_metrics`` (seconds); a drop
#: and `TraceRecorder.close` write them at once.
METRICS_SECONDS = 1.0
#: The recorder's buffer bound (events) and its time bound (seconds).
MAX_BUFFER = 512
FLUSH_SECONDS = 0.25
#: Kinds that close a unit of work: written at once, so the diagrams never wait for the
#: next event after a quiet phase (a browser confirmation, a long timing check).
FLUSH_KINDS = frozenset({"run.start", "run.end", "test.start", "test.strategy",
                         "test.end", "finding"})
#: `TraceRecorder.emit`'s default ``t``: the event is happening now.
NOW = object()
#: Characters of a probe value kept as a preview (escaped by every renderer).
MAX_PREVIEW = 64

APP = "app:target"
BROWSER = "actor:browser"
EXPLORER = "actor:explorer"
SPIDER = "actor:spider"
TOOL = "actor:tool"
#: The browser the tool drives for the M6 confirmation (FR-FUZZ-62): its own actor, so
#: its flows never share an id or an evidence count with the tool's HTTP exchanges.
M6_BROWSER = "actor:tool-browser"
#: An identifier-like path segment `safe_ref` withheld; grouped as ``{id}``.
REDACTED_SEGMENT = "{redacted}"
#: A run of identifier characters inside a path segment (`safe_ref`, BUG-0521).
_TOKEN_RUN = re.compile(r"[A-Za-z0-9_\-+=]{8,}")
#: An entity kind's rank: the strongest kind any event gives an entity is kept, so the
#: kind does not depend on event order (an interface also loaded as a page).
_KIND_RANK = {"page": 0, "interface": 1}

# --- the execution context: which test, strategy and role a send belongs to ----------
_TEST: contextvars.ContextVar[str | None] = contextvars.ContextVar("fl_trace_test",
                                                                  default=None)
_STRATEGY: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "fl_trace_strategy", default=None)
_ROLE: contextvars.ContextVar[str | None] = contextvars.ContextVar("fl_trace_role",
                                                                  default=None)
_EXCHANGES: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "fl_trace_exchanges", default=None)
#: The keys of the confirmation steps (`emit_step`) recorded in the current strategy run.
_STEPS: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "fl_trace_steps", default=None)

#: Roles a send can carry. ``probe`` is a send whose code did not say what it is;
#: ``bind`` is the fetch of the page a fresh form value is bound from before a send
#: (FR-FUZZ-67).
ROLES = ("baseline", "mutation", "control", "follow-up", "restore", "retry",
         "probe", "bind")


@contextlib.contextmanager
def role(name: str):
    """Mark the sends made inside as ``name`` (a `ROLES` value). Used only where the
    code knows: the pipeline's fingerprint baseline, a differential's base and variant
    sends, a timing check's baseline samples and delays, a PRG restore."""
    token = _ROLE.set(name)
    try:
        yield
    finally:
        _ROLE.reset(token)


@contextlib.contextmanager
def test_scope(test_id: str | None):
    token = _TEST.set(test_id)
    try:
        yield
    finally:
        _TEST.reset(token)


@contextlib.contextmanager
def strategy_scope(name: str | None):
    """The sends inside belong to strategy ``name``; their exchange keys are collected
    (`collected`), and the keys of its confirmation steps (`collected_steps`), so a
    finding can cite exactly them."""
    token = _STRATEGY.set(name)
    keys = _EXCHANGES.set([])
    steps = _STEPS.set([])
    try:
        yield
    finally:
        _STRATEGY.reset(token)
        _EXCHANGES.reset(keys)
        _STEPS.reset(steps)


def collected() -> list[str]:
    """The exchange keys recorded in the current `strategy_scope`."""
    return list(_EXCHANGES.get() or [])


def collected_steps() -> list[str]:
    """The confirmation-step keys (`emit_step`) recorded in the current `strategy_scope`
    (FR-FUZZ-62)."""
    return list(_STEPS.get() or [])


def current() -> tuple[str | None, str | None, str | None]:
    return _TEST.get(), _STRATEGY.get(), _ROLE.get()


# --- interface identity ----------------------------------------------------------------
def interface_path(url: str) -> tuple[str, bool]:
    """The path an interface is keyed by, and whether segments were grouped: a segment
    that is a crawled placeholder (``{id}``), id-shaped (`core.pathtemplate.id_shaped`)
    or a JavaScript placeholder becomes ``{id}``. Nothing else is merged -- distinct
    words stay distinct interfaces. The query, the fragment and a segment's
    ``;name=value`` parameters are never part of it (BUG-0514: ``;jsessionid=``)."""
    path = urlsplit(url).path or "/"
    out, grouped = [], False
    for seg in path.split("/"):
        shaped, kept = _segment(seg.split(";", 1)[0])
        out.append(kept)
        grouped = grouped or shaped
    return "/".join(out) or "/", grouped


@functools.lru_cache(maxsize=65536)
def _segment(seg: str) -> tuple[bool, str]:
    """``(grouped, segment as kept)`` for one path segment (`interface_path`)."""
    from urllib.parse import unquote

    from fuzzlab.core.pathtemplate import JS_PLACEHOLDERS, id_shaped
    raw = unquote(seg)
    if raw == REDACTED_SEGMENT:
        return True, "{id}"
    if raw.startswith("{") and raw.endswith("}") and len(raw) > 2:
        return False, raw
    if raw and (raw in JS_PLACEHOLDERS or id_shaped(raw)):
        return True, "{id}"
    return False, seg


def interface_id(origin: str, method: str, url: str) -> str:
    return f"iface:{origin}|{(method or 'GET').upper()}|{interface_path(url)[0]}"


def origin_id(origin: str) -> str:
    return f"origin:{origin}"


#: What `safe_ref` returns for a URL it cannot parse (as 7393c90's did).
_WITHHELD = "(unparseable URL withheld)"


def safe_ref(url: str) -> str:
    """A URL fit for a diagram or an export (BUG-0514):

    - sensitive query values replaced and identifier-like ones blanked, a SPA route's
      query too
      (`core.redaction.redact_url_identifiers`);
    - userinfo, sensitive ``;name=value`` path parameters and a query-shaped fragment's
      sensitive values (``#access_token=…``) replaced, by the record boundary
      (`core.redaction.redact_for_record`, PA-0003: one implementation);
    - every other ``;name=value`` and fragment value that looks like an identifier
      blanked;
    - an identifier-like path segment (a JWT, a reset token, a UUID) replaced by
      `REDACTED_SEGMENT`, which an interface groups as ``{id}``.

    Layered (BUG-0556 r6, `core.redaction.LAYERED`): the pushed tree's own `safe_ref`
    runs first (`core.redaction_floor.safe_ref`, frozen at 7393c90: its URL redactor,
    then its record redactor's userinfo rule, then this blanking) and the walk's steps
    above run on its output only. 144d234 ran the walk first, and where a userinfo
    password held a ``;`` or ``&`` before a redacted piece the walk cut the ``@`` the
    record rule needed, keeping the password's start (R1, 775 URLs; 146 stored by
    `import_spider` through the trace recorder).

    Total: a URL it cannot parse is withheld whole (the floor withholds what 7393c90
    withheld: a URL ``urlsplit`` rejects that holds a ``?``; one without a ``?`` is
    redacted like any other, not withheld, as on 7393c90)."""
    from fuzzlab.core import redaction_floor as _floor
    from fuzzlab.core.redaction import _walk_record, _walk_url
    text = _floor.safe_ref(url)
    if text == _WITHHELD:
        return text
    try:
        text = _walk_record("", _walk_url(text, identifiers=True))
        return _blank_identifiers(text)
    except Exception:  # noqa: BLE001 - never let a malformed URL leak through
        return _WITHHELD


def _blank_identifiers(url: str) -> str:
    """`safe_ref`'s last step: identifier-like path segments, matrix values and fragment
    values (the query's are already done)."""
    from urllib.parse import unquote

    from fuzzlab.core.redaction import looks_like_identifier
    head, hashmark, fragment = url.partition("#")
    base, qmark, query = head.partition("?")
    scheme, sep, rest = base.partition("://")
    if not sep:
        scheme, rest = "", base
    authority, slash, path = rest.partition("/") if sep else ("", "", rest)
    segments = []
    for seg in path.split("/"):
        name, semi, params = seg.partition(";")
        if name and looks_like_identifier(unquote(name)):
            name = REDACTED_SEGMENT
        elif name:
            # a token inside a segment, as in a URL embedded in text: ``cb/<tok>)``,
            # ``cb/<tok>`'' (BUG-0521)
            name = _TOKEN_RUN.sub(
                lambda m: REDACTED_SEGMENT if looks_like_identifier(m.group(0))
                else m.group(0), name)
        if semi:
            params = ";".join(
                f"{k}=" if eq and looks_like_identifier(unquote(v)) else part
                for part in params.split(";")
                for k, eq, v in [part.partition("=")])
        segments.append(name + semi + params)
    path = "/".join(segments)
    if hashmark and "=" in fragment:
        route, q, fquery = fragment.rpartition("?") if "?" in fragment \
            else ("", "", fragment)
        fquery = "&".join(
            f"{k}=" if eq and looks_like_identifier(unquote(v)) else part
            for part in fquery.split("&") for k, eq, v in [part.partition("=")])
        fragment = route + q + fquery
    out = (f"{scheme}://{authority}{slash}" if sep else "") + path
    return out + qmark + query + hashmark + fragment


def data_category(name: str) -> str:
    """A parameter name's data category, by name only (never its value)."""
    from fuzzlab.core.redaction import is_credential_name, is_sensitive_name
    if is_credential_name(name):
        return "credential"
    if is_sensitive_name(name):
        return "sensitive"
    return "data"


def value_digest(value) -> tuple[str, int]:
    text = "" if value is None else str(value)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16], len(text)


def value_preview(name: str, value) -> str | None:
    """A short preview of a value the tool itself sent, or None when the parameter's
    name is sensitive (the tool never shows what it put in a credential field)."""
    if data_category(name) != "data":
        return None
    text = "" if value is None else str(value)
    return text[:MAX_PREVIEW] + ("…" if len(text) > MAX_PREVIEW else "")


# --- the write-site boundary (PA-0100) ------------------------------------------------
#: Characters a string in an event body keeps at most.
MAX_TEXT = 512
#: Body keys whose *values* are names, labels or the tool's own words, never target
#: data: exempt from blanking by key name (``auth``, ``session``, ``identity`` and
#: ``profile`` hold an account's *name*, which the name rule would otherwise blank;
#: ``error`` an exception class; ``detail`` a verdict's own fields, whose nested keys
#: still pass the rule). Producers put nothing else there (BUG-0514).
_SCHEMA_KEYS = frozenset({"param", "params", "fields", "label", "kind", "role", "outcome",
                          "strategy", "mechanism", "vuln_class", "category", "rule",
                          "location", "src", "ref", "via", "delivery", "error", "detail",
                          "identity", "profile", "auth", "session", "test", "action"})
#: Body keys that hold a URL or a path, absolute or relative: always through `safe_ref`
#: (``location`` is also an injection location's word, which has no ``/``).
_URL_KEYS = frozenset({"url", "location", "redirect", "referer", "route", "base_url",
                       "page_url", "found_from", "example", "initiator"})


def scrub_event(value, key: str | None = None):
    """The last redaction an event body passes before it is written (PA-0100): every
    URL-looking string through `safe_ref`, any value under a sensitive key name blanked
    (``""``; the event schema's own keys excepted), every string capped at `MAX_TEXT`.
    Producers already build bodies from redacted values; this is the boundary."""
    from fuzzlab.core.redaction import is_sensitive_name
    if isinstance(value, dict):
        return {str(k): ("" if (str(k) not in _SCHEMA_KEYS and is_sensitive_name(str(k)))
                         else scrub_event(v, str(k))) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_event(v, key) for v in value]
    if isinstance(value, str):
        url_shaped = "://" in value or (key in _URL_KEYS and "/" in value)
        text = safe_ref(value) if url_shaped else value
        return text[:MAX_TEXT] + ("…" if len(text) > MAX_TEXT else "")
    return value


# --- the reducer ------------------------------------------------------------------------
@dataclass
class _Acc:
    """One entity or flow touched by a batch: what the batch adds to it."""
    row: dict
    attrs: dict = field(default_factory=dict)
    keys: set = field(default_factory=set)


def _strong(a: str, b: str) -> str:
    return a if KNOWLEDGE.index(a) >= KNOWLEDGE.index(b) else b


def _add(attrs: dict, key: str, value) -> None:
    if value is None or value == "":
        return
    attrs.setdefault(key, set()).add(value if isinstance(value, (str, int, float))
                                     else json.dumps(value, sort_keys=True))


class _Batch:
    def __init__(self):
        self.entities: dict[str, _Acc] = {}
        self.flows: dict[str, _Acc] = {}

    def entity(self, eid, kind, label, *, parent=None, knowledge="observed", t=None,
               key=None, basis=None, **attrs) -> None:
        acc = self.entities.get(eid)
        if acc is None:
            acc = self.entities[eid] = _Acc({"eid": eid, "kind": kind, "label": label,
                                             "parent": parent, "knowledge": knowledge,
                                             "first": t, "last": t})
        r = acc.row
        r["kind"] = _stronger_kind(r["kind"], kind)
        r["knowledge"] = _strong(r["knowledge"], knowledge)
        r["parent"] = r["parent"] or parent
        _span(r, t)
        _add(acc.attrs, "basis", basis)
        for k, v in attrs.items():
            for item in (v if isinstance(v, (list, tuple, set)) else [v]):
                _add(acc.attrs, k, item)
        if key:
            acc.keys.add(key)

    def flow(self, src, dst, view, protocol, *, knowledge="observed", t=None, key=None,
             basis=None, **attrs) -> None:
        fid = f"flow:{view}:{src}->{dst}:{protocol}"
        acc = self.flows.get(fid)
        if acc is None:
            acc = self.flows[fid] = _Acc({"fid": fid, "src": src, "dst": dst, "view": view,
                                          "protocol": protocol, "knowledge": knowledge,
                                          "first": t, "last": t})
        r = acc.row
        r["knowledge"] = _strong(r["knowledge"], knowledge)
        _span(r, t)
        _add(acc.attrs, "basis", basis)
        for k, v in attrs.items():
            for item in (v if isinstance(v, (list, tuple, set)) else [v]):
                _add(acc.attrs, k, item)
        if key:
            acc.keys.add(key)


def _stronger_kind(a: str, b: str) -> str:
    """The kind an entity keeps whatever the order (`_KIND_RANK`; ties keep ``a``)."""
    return b if _KIND_RANK.get(b, -1) > _KIND_RANK.get(a, -1) else a


def _span(row: dict, t) -> None:
    if t is None:
        return
    row["first"] = t if row["first"] is None else min(row["first"], t)
    row["last"] = t if row["last"] is None else max(row["last"], t)


def _origin_entities(b: _Batch, origin: str, t, key, basis: str) -> None:
    b.entity(APP, "application", "Target application", t=t, key=key,
             basis="explicit configuration: the run's base URL and scope")
    b.entity(origin_id(origin), "origin", origin, parent=APP, t=t, key=key, basis=basis,
             internals="unknown: no server-side component is observable from traffic")


def _interface(b: _Batch, origin, method, url, *, t, key, basis, kind="interface",
               **attrs) -> str:
    path, grouped = interface_path(url)
    eid = f"iface:{origin}|{(method or 'GET').upper()}|{path}"
    extra = {"grouping": "inferred: id-shaped path segments grouped"} if grouped else {}
    # an interface whose path holds a template segment is a grouping: inferred, never
    # observed as such (the requests to it are; BUG-0515)
    templated = "{" in path
    b.entity(eid, kind, f"{(method or 'GET').upper()} {path}", parent=origin_id(origin),
             knowledge="inferred" if templated else "observed",
             t=t, key=key, basis=basis, example=safe_ref(url) if grouped else None,
             **extra, **attrs)
    return eid


def _observer(body: dict) -> str:
    """Who made an observed request: the spider itself for its own page loads (``by``
    "crawler", or a ``discovered_pages`` row from before ``by`` existed), else the
    browser (BUG-0515: the spider's loads are not browser traffic)."""
    by = body.get("by")
    if by == "crawler" or (by is None and body.get("src") == "spider"
                           and str(body.get("ref") or "").startswith("discovered_pages")):
        return SPIDER
    return BROWSER


def _apply(b: _Batch, key: str, kind: str, body: dict, t) -> None:
    """One event's contribution to the model (the reducer's whole vocabulary)."""
    if kind == "run.start":
        b.entity(TOOL, "tool", "fuzzlab (testing infrastructure)", t=t, key=key,
                 basis="explicit configuration: this run")
        for origin in body.get("origins") or []:
            _origin_entities(b, origin, t, key, "explicit configuration: run scope")
    elif kind in ("observe.exchange", "observe.page"):
        origin = body.get("origin")
        if not origin:
            return
        src = body.get("src") or "capture"
        actor = _observer(body)
        basis = (f"browser instrumentation ({src}): {body.get('ref')}" if actor == BROWSER
                 else f"crawler request ({src}): {body.get('ref')}")
        if actor == BROWSER:
            b.entity(BROWSER, "actor", "Browser / client application", t=t, key=key,
                     basis=f"browser instrumentation ({src})")
        else:
            b.entity(SPIDER, "actor", "Spider (crawler, tool)", t=t, key=key,
                     basis="tool: the spider's own page loads")
        _origin_entities(b, origin, t, key, basis)
        params = body.get("params") or []
        iface = _interface(b, origin, body.get("method"), body.get("url") or "", t=t,
                           key=key, basis=basis,
                           kind="page" if kind == "observe.page" else "interface",
                           status=body.get("status") or None, ctype=body.get("ctype"),
                           param=[f"{n} ({loc})" for n, loc in params])
        protocol = "ws" if body.get("ws") else "http"
        refused = None
        if body.get("delivery") and body["delivery"] != "sent":
            # learnt in the browser and blocked: never sent (BUG-0515)
            protocol, refused = "blocked", body["delivery"]
        b.flow(actor, iface, "app", protocol, t=t, key=key, basis=basis, refused=refused,
               status=body.get("status") or None, error=body.get("error"),
               auth=body.get("profile"), workflow=body.get("action"),
               initiator=body.get("referer"),
               redirect=body.get("redirect") or body.get("location"),
               via=body.get("via"), delivery=body.get("delivery"),
               outcome=body.get("outcome"),
               data=[f"{data_category(n)}:{loc}" for n, loc in params],
               ws=body.get("ws"))
    elif kind == "observe.external":
        host = body.get("host") or "?"
        b.entity(BROWSER, "actor", "Browser / client application", t=t, key=key,
                 basis=f"browser instrumentation ({body.get('src')})")
        b.entity(f"ext:{host}", "external", host, t=t, key=key,
                 basis="a page referenced it; refused by scope, never contacted")
        b.flow(BROWSER, f"ext:{host}", "app", "http", t=t, key=key,
               basis="attempted by the browser, refused by the scope guard",
               refused=body.get("count"))
    elif kind == "observe.action":
        b.entity(EXPLORER, "actor", "Explorer (automated browser user)", t=t, key=key,
                 basis="tool action: the disco explorer's action log")
    elif kind == "exchange":
        origin = body.get("origin")
        if not origin:
            return
        b.entity(TOOL, "tool", "fuzzlab (testing infrastructure)", t=t, key=key,
                 basis="explicit configuration: this run")
        _origin_entities(b, origin, t, key, "tool exchange (this run)")
        iface = _interface(b, origin, body.get("method"), body.get("url") or "", t=t,
                           key=key, basis="tool exchange (this run)",
                           tested=body.get("test"))
        b.flow(TOOL, iface, "test", "http", t=t, key=key,
               basis="tool exchange (this run)", role=body.get("role"),
               outcome=body.get("outcome"), status=body.get("status"),
               strategy=body.get("strategy"), auth=body.get("identity"),
               test=body.get("test"), param=body.get("param"))
    elif kind == "browser.step":
        # FR-FUZZ-62: the M6 browser's own store and observe loads that went out, as
        # its own testing-overlay flow (never merged with the tool's exchanges)
        origin = body.get("origin")
        if body.get("step") not in ("store", "navigate") or not origin or \
                body.get("outcome") == "not_sent":
            return
        basis = "the tool's browser (M6 confirmation, this run)"
        b.entity(M6_BROWSER, "actor", "Browser driven by the tool (M6)", t=t, key=key,
                 basis=basis)
        _origin_entities(b, origin, t, key, basis)
        iface = _interface(b, origin, body.get("method"), body.get("url") or "", t=t,
                           key=key, basis=basis, tested=body.get("test"))
        b.flow(M6_BROWSER, iface, "test", "http", t=t, key=key, basis=basis,
               step=body.get("step"), outcome=body.get("outcome"),
               status=body.get("status"), strategy=body.get("strategy"),
               test=body.get("test"), param=body.get("param"))
    elif kind == "finding":
        origin = body.get("origin")
        if origin:
            iface = _interface(b, origin, body.get("method"), body.get("url") or "", t=t,
                               key=key, basis="evaluator finding (this run)",
                               finding=body.get("finding_id"))
            b.flow(TOOL, iface, "test", "http", t=t, key=key,
                   basis="evaluator finding (this run)", finding=body.get("finding_id"))


def reduce(conn, run_id: int, events) -> None:
    """Fold ``events`` (``(key, kind, body, t)``) into the run's ``dg_*`` rows. Safe to
    repeat and order-independent (module docstring). The caller commits."""
    b = _Batch()
    for key, kind, body, t in events:
        _apply(b, key, kind, body if isinstance(body, dict) else {}, t)
    for acc in b.entities.values():
        r = acc.row
        old = conn.execute("SELECT kind, parent, label, knowledge, first_seen, last_seen, "
                           "attrs FROM dg_entity WHERE run_id=? AND eid=?",
                           (run_id, r["eid"])).fetchone()
        attrs, first, last, knowledge, parent, kind = _merge(old, acc, r)
        conn.execute(
            "INSERT INTO dg_entity (run_id, eid, kind, parent, label, knowledge, "
            "first_seen, last_seen, attrs) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id, eid) DO UPDATE SET kind=excluded.kind, "
            "parent=excluded.parent, "
            "knowledge=excluded.knowledge, first_seen=excluded.first_seen, "
            "last_seen=excluded.last_seen, attrs=excluded.attrs",
            (run_id, r["eid"], kind, parent, r["label"], knowledge, first, last,
             json.dumps(attrs, sort_keys=True)))
        _evidence(conn, run_id, r["eid"], acc.keys)
    for acc in b.flows.values():
        r = acc.row
        old = conn.execute("SELECT src, dst, view, knowledge, first_seen, last_seen, "
                           "attrs FROM dg_flow WHERE run_id=? AND fid=?",
                           (run_id, r["fid"])).fetchone()
        attrs, first, last, knowledge, _p, _k = _merge(old, acc, r)
        conn.execute(
            "INSERT INTO dg_flow (run_id, fid, src, dst, view, protocol, knowledge, "
            "first_seen, last_seen, attrs) VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id, fid) DO UPDATE SET knowledge=excluded.knowledge, "
            "first_seen=excluded.first_seen, last_seen=excluded.last_seen, "
            "attrs=excluded.attrs",
            (run_id, r["fid"], r["src"], r["dst"], r["view"], r["protocol"], knowledge,
             first, last, json.dumps(attrs, sort_keys=True)))
        _evidence(conn, run_id, r["fid"], acc.keys)


def _merge(old, acc: _Acc, r: dict):
    attrs = {k: set(v) for k, v in acc.attrs.items()}
    more_before: set[str] = set()
    first, last, knowledge, parent = r["first"], r["last"], r["knowledge"], r.get("parent")
    kind = r.get("kind")
    if old is not None:
        prev = json.loads(old["attrs"] or "{}")
        for k, v in prev.items():
            if k.endswith("_more"):
                if v:
                    more_before.add(k[:-5])
                continue
            attrs.setdefault(k, set()).update(v)
        if old["first_seen"] is not None:
            first = old["first_seen"] if first is None else min(first, old["first_seen"])
        if old["last_seen"] is not None:
            last = old["last_seen"] if last is None else max(last, old["last_seen"])
        knowledge = _strong(old["knowledge"], knowledge)
        parent = parent or (old["parent"] if "parent" in old.keys() else None)
        if "kind" in old.keys() and kind is not None:
            kind = _stronger_kind(old["kind"], kind)
    # the MAX_ATTR_VALUES smallest values, and whether there were more: both the same
    # whatever the order the events came in, and equal to a rebuild (BUG-0516)
    out: dict = {}
    for k, values in attrs.items():
        ordered = sorted(values, key=lambda x: (str(type(x)), x))
        out[k] = ordered[:MAX_ATTR_VALUES]
        if k in more_before or len(ordered) > MAX_ATTR_VALUES:
            out[k + "_more"] = True
    return out, first, last, knowledge, parent, kind


def _evidence(conn, run_id: int, ref: str, keys) -> None:
    conn.executemany("INSERT OR IGNORE INTO dg_evidence (run_id, ref, event_key) "
                     "VALUES (?,?,?)", [(run_id, ref, k) for k in sorted(keys)])


def rebuild(conn, run_id: int, *, chunk: int = 2000) -> int:
    """Replay a run's events into fresh ``dg_*`` rows; returns the events replayed."""
    conn.execute("DELETE FROM dg_entity WHERE run_id=?", (run_id,))
    conn.execute("DELETE FROM dg_flow WHERE run_id=?", (run_id,))
    conn.execute("DELETE FROM dg_evidence WHERE run_id=?", (run_id,))
    n, after = 0, 0
    while True:
        rows = conn.execute("SELECT id, key, kind, body, t FROM trace_event WHERE "
                            "run_id=? AND id>? ORDER BY id LIMIT ?",
                            (run_id, after, chunk)).fetchall()
        if not rows:
            break
        reduce(conn, run_id, [(r["key"], r["kind"], json.loads(r["body"]), r["t"])
                              for r in rows])
        n += len(rows)
        after = rows[-1]["id"]
    conn.commit()
    return n


# --- the one writer ---------------------------------------------------------------------
class TraceRecorder:
    """Buffers a run's events and writes each batch with its reduction in one
    transaction (module docstring). Not thread-safe by design: one recorder per
    producer thread, on that thread's `Store`."""

    def __init__(self, store, run_id: int, *, max_buffer: int = MAX_BUFFER,
                 flush_seconds: float = FLUSH_SECONDS, clock=time.monotonic):
        self.store = store
        self.run_id = run_id
        self.max_buffer = max(1, int(max_buffer))
        self.flush_seconds = flush_seconds
        self.clock = clock
        self._buffer: list[tuple] = []
        self._oldest: float | None = None
        row = store.conn.execute("SELECT COALESCE(MAX(seq), 0) m FROM trace_event "
                                 "WHERE run_id=?", (run_id,)).fetchone()
        self._seq = int(row["m"] if hasattr(row, "keys") else row[0])
        self.stats = {"emitted": 0, "written": 0, "duplicates": 0, "dropped": 0,
                      "flushes": 0, "forced_flushes": 0, "flush_ms": 0.0,
                      "max_lag_ms": 0.0, "buffer_peak": 0}
        self._metrics_at: float | None = None
        self._dropped_written = 0

    def emit(self, kind: str, body: dict, *, key: str | None = None,
             scope: str | None = None, t=NOW) -> str:
        """Queue one event; returns its key (``key`` given: the producer's own stable
        key, so a repeat is a duplicate; else a fresh one). ``t``: when it happened --
        `NOW` (default) for an event the producer is witnessing, the source's own time,
        or None when the source does not record one (never replaced by "now")."""
        key = key or f"{kind}:{uuid.uuid4().hex[:20]}"
        self._seq += 1
        self._buffer.append((key, kind, scope, self._seq,
                             time.time() if t is NOW else t, body))
        self.stats["emitted"] += 1
        self.stats["buffer_peak"] = max(self.stats["buffer_peak"], len(self._buffer))
        now = self.clock()
        if self._oldest is None:
            self._oldest = now
        if len(self._buffer) >= self.max_buffer:
            self.stats["forced_flushes"] += 1
            self.flush()
        elif kind in FLUSH_KINDS or now - self._oldest >= self.flush_seconds:
            self.flush()
        return key

    def flush(self) -> None:
        if not self._buffer:
            return
        batch, self._buffer = self._buffer, []
        lag = (self.clock() - self._oldest) * 1000 if self._oldest is not None else 0.0
        self._oldest = None
        started = time.perf_counter()
        conn = self.store.conn
        try:
            fresh = []
            for key, kind, scope, seq, t, body in batch:
                body = scrub_event(body)
                cur = conn.execute(
                    "INSERT OR IGNORE INTO trace_event (run_id, key, v, kind, scope, seq, "
                    "t, body) VALUES (?,?,?,?,?,?,?,?)",
                    (self.run_id, key, EVENT_VERSION, kind, scope, seq, t,
                     json.dumps(body, sort_keys=True, default=str)))
                if cur.rowcount:
                    fresh.append((key, kind, body, t))
                else:
                    self.stats["duplicates"] += 1
            reduce(conn, self.run_id, fresh)
            conn.commit()
            self.stats["written"] += len(fresh)
        except Exception as exc:  # noqa: BLE001 - counted and logged, never silent
            with contextlib.suppress(Exception):
                conn.rollback()
            self.stats["dropped"] += len(batch)
            from fuzzlab.core.obs import get_logger
            get_logger("trace").warning("trace batch not written",
                                        extra={"events": len(batch),
                                               "error": type(exc).__name__})
        self.stats["flushes"] += 1
        self.stats["flush_ms"] += (time.perf_counter() - started) * 1000
        self.stats["max_lag_ms"] = max(self.stats["max_lag_ms"], lag)
        # live: the counters a running run's status shows (BUG-0516); a drop at once
        if self._metrics_at is None or self.stats["dropped"] != self._dropped_written \
                or self.clock() - self._metrics_at >= METRICS_SECONDS:
            self._write_metrics()

    def _write_metrics(self) -> None:
        """Record the counters in ``run_metrics`` (``trace_*``), replacing the last."""
        self._metrics_at = self.clock()
        rows = [(self.run_id, f"trace_{k}", float(v)) for k, v in self.stats.items()]
        with contextlib.suppress(Exception):
            self.store.conn.execute("DELETE FROM run_metrics WHERE run_id=? AND key LIKE "
                                    "'trace\\_%' ESCAPE '\\'", (self.run_id,))
            self.store.conn.executemany(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)", rows)
            self.store.conn.commit()
            self._dropped_written = self.stats["dropped"]

    def close(self) -> dict:
        """Flush and record the counters in ``run_metrics`` (``trace_*``)."""
        self.flush()
        self._write_metrics()
        return dict(self.stats)


# --- the process-wide hook the execution points call -----------------------------------
_RECORDER: contextvars.ContextVar[TraceRecorder | None] = contextvars.ContextVar(
    "fl_trace_recorder", default=None)


@contextlib.contextmanager
def recording(recorder: TraceRecorder | None):
    """Make ``recorder`` the one the execution points in this context write to."""
    token = _RECORDER.set(recorder)
    try:
        yield recorder
    finally:
        _RECORDER.reset(token)


def active() -> TraceRecorder | None:
    return _RECORDER.get()


def emit(kind: str, body: dict, **kw) -> str | None:
    """Record an event with the active recorder; no recorder, no event (and no cost)."""
    rec = _RECORDER.get()
    if rec is None:
        return None
    return rec.emit(kind, body, **kw)


def emit_step(kind: str, body: dict, *, scope: str | None = None, t=NOW) -> str | None:
    """Record one confirmation step (FR-FUZZ-62: ``browser.step``, ``oob.wait``) and
    add its key to the current strategy run's `collected_steps`, which its
    ``test.strategy`` and ``finding`` cite. ``scope`` defaults to the body's test
    (``test:<id>``), else ``run``. No recorder, no event."""
    rec = _RECORDER.get()
    if rec is None:
        return None
    if scope is None:
        scope = f"test:{body['test']}" if body.get("test") else "run"
    key = rec.emit(kind, body, scope=scope, t=t)
    steps = _STEPS.get()
    if steps is not None and key:
        steps.append(key)
    return key
