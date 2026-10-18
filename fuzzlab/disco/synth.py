"""``capture.jsonl`` -> an OpenAPI 3.1-shaped live endpoint inventory (pure; no traffic).

The pipeline, each step from what was captured only (never a framework's routing
conventions):

1. **Path templating.** Every path segment is classified across all samples of the same
   origin and shape: an integer is ``int``, a UUID ``uuid``, a ULID / long hex / other
   identifier-like token (`core.redaction.looks_like_identifier`, SP-18) ``id``; and a
   position (not the first) whose value varies across at least `SLUG_MIN_DISTINCT`
   sibling paths (same segments everywhere else), every value seen as data in a
   captured response, is a ``slug``. Such positions become ``{p1}``, ``{p2}``...,
   so ``/users/17/orders`` and ``/users/42/orders`` are one ``/users/{p1}/orders``.
2. **Endpoint key** = (origin, method, template, request content-type family).
3. **Body schemas**, merged across samples (genson-style): type unions per field;
   ``required`` = present in every sample of that object; ``enum`` for at most
   `ENUM_MAX` distinct values over at least `ENUM_MIN_SAMPLES` samples; formats (email,
   uuid, date-time, date, uri, ipv4, numeric-string); observed lengths and ranges kept
   under ``x-observed`` -- observations, never constraints. Form-urlencoded and multipart
   bodies are flattened into the same field model. An enum needs two or more distinct
   *string* values (one value is a constant the explorer itself typed; numbers keep only
   their observed range); a value redaction replaced is never an enum or an example, and
   a field seen only redacted is marked ``x-redacted``.
4. **Query parameters** the same way; **headers** classed ``session`` (a sensitive name
   or a redacted value), ``static`` (one value in every sample; the value is kept, so the
   fuzzer can send the browser's own headers, D69) or ``varies``.
5. **Response schemas** per status. Fields seen in a response but never in any request
   to the same resource are listed as mass-assignment candidates.
6. **Dependencies.** A value in a response of A that later appears in a request to B
   (path parameter, query or body) is an edge A -> B with the JSONPath that extracts it.
   Only identifier-like values count (a UUID, an identifier-shaped string, an integer of
   `DEP_MIN_INT_DIGITS`+ digits, or a smaller integer when it fills a templated path
   parameter or an ``id``-named body field), so ``1`` and ``true`` make no edges.

The output carries an ``x-disco`` extension on each operation: sample count, the UI
actions and auth profiles that produced it, observed vs inferred, headers, auth,
dependencies, latency. Path-like literals mined from captured JavaScript bundles
(``fetch(`` / ``axios`` / ``.get(`` ... call sites) are listed as ``observed: false``
candidates, never as operations.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from statistics import median
from urllib.parse import parse_qsl, urlsplit

from fuzzlab.core.redaction import PLACEHOLDER, is_sensitive_name, looks_like_identifier
from fuzzlab.core.urls import canonical_origin
from fuzzlab.disco.capture import CaptureRecord

ENUM_MAX = 5
ENUM_MIN_SAMPLES = 4
SLUG_MIN_DISTINCT = 3
DEP_MIN_INT_DIGITS = 4
#: A JSON document deeper than this is not walked for schema or dependencies.
MAX_DEPTH = 32
#: Distinct values remembered per field (enough to decide an enum).
MAX_DISTINCT = ENUM_MAX + 1

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ULID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_INT = re.compile(r"^-?[0-9]{1,18}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,24}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_URI = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s]{1,2048}$")
_NUMSTR = re.compile(r"^-?\d{1,18}(\.\d{1,18})?$")
#: Paths that are static assets, never API surface.
_STATIC_EXT = re.compile(r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|"
                         r"eot|otf|mp4|webm|mp3|wav)$", re.I)
_STATIC_CTYPES = ("image/", "font/", "text/css", "javascript", "audio/", "video/")
#: Headers never classified (hop-by-hop, computed by the client, or the proxy's).
_IGNORED_HEADERS = frozenset({"host", "content-length", "connection", "proxy-connection",
                              "keep-alive", "transfer-encoding", "te", "upgrade",
                              "accept-encoding", "pragma", "cache-control", "if-none-match",
                              "if-modified-since"})
#: JS call sites whose first literal is a request path.
_JS_CALL = re.compile(r"""(?:fetch|axios(?:\.(get|post|put|patch|delete))?|\.(get|post|put|patch|delete)|url\s*:)\s*\(?\s*[`'"](/[A-Za-z0-9_\-./{}:$]{1,200})[`'"]""")


# --- segment classification ------------------------------------------------------------

def segment_kind(seg: str) -> str | None:
    """``int`` / ``uuid`` / ``id`` for a value segment, None for a literal."""
    if _INT.match(seg):
        return "int"
    if _UUID.match(seg):
        return "uuid"
    if _ULID.match(seg) or _HEX.match(seg) or looks_like_identifier(seg):
        return "id"
    return None


def content_family(ctype: str | None) -> str:
    ct = (ctype or "").split(";", 1)[0].strip().lower()
    if not ct:
        return "none"
    if ct == "application/json" or ct.endswith("+json"):
        return "json"
    if ct == "application/x-www-form-urlencoded":
        return "form"
    if ct.startswith("multipart/form-data"):
        return "multipart"
    if ct.startswith("text/"):
        return "text"
    return "other"


def is_static(rec: CaptureRecord) -> bool:
    path = urlsplit(rec.url).path
    if rec.method in ("GET", "HEAD") and _STATIC_EXT.search(path):
        return True
    ctype = (rec.res_ctype or "").lower()
    return rec.method in ("GET", "HEAD") and any(t in ctype for t in _STATIC_CTYPES)


def template_paths(paths: list[tuple[str, str]], data_values: frozenset[str] = frozenset()
                   ) -> dict[tuple[str, str], tuple[str, list[str]]]:
    """``(origin, path) -> (template, [kind per {pN}])`` for every distinct path.

    A literal segment is a ``slug`` only when it varies across `SLUG_MIN_DISTINCT`
    sibling paths **and** every one of its values was seen as data -- a string value in
    a captured JSON response (``data_values``) -- and never in the first segment. Without
    that, an API's resource names (``/api/Users/``, ``/api/Products/``) and an app's
    top-level routes (``/profile``, ``/redirect``) collapsed into one endpoint
    (BUG-0501, measured on Juice Shop)."""
    split = {(o, p): [s for s in p.split("/") if s != ""] for o, p in paths}
    kinds: dict[tuple[str, str], list[str | None]] = {
        key: [segment_kind(s) for s in segs] for key, segs in split.items()}
    # slugs: a position varying across >= SLUG_MIN_DISTINCT siblings (all else equal)
    groups: dict[tuple, set[str]] = defaultdict(set)
    for (origin, path), segs in split.items():
        k = kinds[(origin, path)]
        for i in range(len(segs)):
            if k[i] is not None:
                continue
            shape = tuple("{}" if (j == i or k[j]) else s for j, s in enumerate(segs))
            groups[(origin, len(segs), i, shape)].add(segs[i])
    for (origin, path), segs in split.items():
        k = kinds[(origin, path)]
        for i in range(len(segs)):
            if k[i] is None and i > 0:
                shape = tuple("{}" if (j == i or k[j]) else s for j, s in enumerate(segs))
                values = groups[(origin, len(segs), i, shape)]
                if len(values) >= SLUG_MIN_DISTINCT and values <= data_values:
                    k[i] = "slug"
    out = {}
    for key, segs in split.items():
        n, parts, pkinds = 0, [], []
        for seg, kind in zip(segs, kinds[key]):
            if kind is None:
                parts.append(seg)
            else:
                n += 1
                parts.append(f"{{p{n}}}")
                pkinds.append(kind)
        template = "/" + "/".join(parts)
        if key[1].endswith("/") and len(segs) and template != "/":
            template += "/"
        out[key] = (template, pkinds)
    return out


# --- schema inference ------------------------------------------------------------------

def string_format(value: str) -> str | None:
    if _UUID.match(value):
        return "uuid"
    if _EMAIL.match(value):
        return "email"
    if _DATETIME.match(value):
        return "date-time"
    if _DATE.match(value):
        return "date"
    if _URI.match(value):
        return "uri"
    try:
        if isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address):
            return "ipv4"
    except ValueError:
        pass
    if _NUMSTR.match(value):
        return "numeric-string"
    return None


def _json_type(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


@dataclass
class SchemaNode:
    """What was observed at one position of many documents (a genson-style builder)."""
    samples: int = 0
    types: set[str] = field(default_factory=set)
    distinct: list = field(default_factory=list)
    distinct_overflow: bool = False
    formats: set = field(default_factory=set)
    min_len: int | None = None
    max_len: int | None = None
    minimum: float | None = None
    maximum: float | None = None
    props: dict[str, "SchemaNode"] = field(default_factory=dict)
    prop_counts: dict[str, int] = field(default_factory=dict)
    objects: int = 0
    items: "SchemaNode | None" = None
    max_items: int = 0

    def add(self, value, depth: int = 0) -> None:
        self.samples += 1
        t = _json_type(value)
        self.types.add(t)
        if depth > MAX_DEPTH:
            return
        if t == "object":
            self.objects += 1
            for k, v in value.items():
                k = str(k)
                self.props.setdefault(k, SchemaNode()).add(v, depth + 1)
                self.prop_counts[k] = self.prop_counts.get(k, 0) + 1
        elif t == "array":
            self.max_items = max(self.max_items, len(value))
            for v in value:
                if self.items is None:
                    self.items = SchemaNode()
                self.items.add(v, depth + 1)
        else:
            if t in ("string", "integer", "number", "boolean"):
                if not self.distinct_overflow and value not in self.distinct:
                    self.distinct.append(value)
                    if len(self.distinct) > MAX_DISTINCT:
                        self.distinct_overflow = True
                        self.distinct = []
            if t == "string":
                self.formats.add(string_format(value))
                n = len(value)
                self.min_len = n if self.min_len is None else min(self.min_len, n)
                self.max_len = n if self.max_len is None else max(self.max_len, n)
            elif t in ("integer", "number"):
                self.minimum = value if self.minimum is None else min(self.minimum, value)
                self.maximum = value if self.maximum is None else max(self.maximum, value)

    def schema(self) -> dict:
        types = sorted(self.types)
        if "integer" in self.types and "number" in self.types:
            types.remove("integer")
        out: dict = {"type": types[0] if len(types) == 1 else types}
        if "object" in self.types:
            out["properties"] = {k: n.schema() for k, n in sorted(self.props.items())}
            req = sorted(k for k, c in self.prop_counts.items() if c == self.objects)
            if req:
                out["required"] = req
        if "array" in self.types and self.items is not None:
            out["items"] = self.items.schema()
        fmts = self.formats - {None}
        if "string" in self.types and len(fmts) == 1 and None not in self.formats:
            out["format"] = fmts.pop()
        strings = [v for v in self.distinct if isinstance(v, str) and v != PLACEHOLDER]
        if not self.distinct_overflow and self.samples >= ENUM_MIN_SAMPLES \
                and 2 <= len(strings) <= ENUM_MAX and self.types == {"string"}:
            out["enum"] = sorted(strings)
        elif strings:
            out["examples"] = sorted(strings)[:3]
        if self.distinct == [PLACEHOLDER]:
            out["x-redacted"] = True
        observed = {}
        if self.min_len is not None:
            observed.update(minLength=self.min_len, maxLength=self.max_len)
        if self.minimum is not None:
            observed.update(minimum=self.minimum, maximum=self.maximum)
        if self.max_items:
            observed["maxItems"] = self.max_items
        if observed:
            out["x-observed"] = observed
        return out


def parse_body(text: str | None, ctype: str | None):
    """A request or response body as a JSON-like value, or None when it is absent,
    omitted by redaction, or unparseable."""
    if not text or text.startswith("__BODY_OMITTED__"):
        return None
    fam = content_family(ctype)
    if fam == "json" or (fam in ("none", "text", "other") and text.lstrip()[:1] in "{["):
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            return None
    if fam == "form":
        return dict(parse_qsl(text, keep_blank_values=True))
    if fam == "multipart":
        return _multipart_fields(text, ctype or "")
    return None


def _multipart_fields(text: str, ctype: str) -> dict | None:
    m = re.search(r'boundary="?([^";]{1,200})"?', ctype)
    if not m:
        return None
    out = {}
    for part in text.split("--" + m.group(1)):
        head, _sep, body = part.partition("\r\n\r\n")
        name = re.search(r'name="([^"]{1,200})"', head)
        if not name:
            continue
        if re.search(r'filename="', head):
            out[name.group(1)] = "<binary>"
        else:
            out[name.group(1)] = body.rstrip("\r\n-")
    return out


def leaves(value, path: str = "$", depth: int = 0):
    """``(jsonpath, scalar)`` for every scalar of a JSON-like value."""
    if depth > MAX_DEPTH:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            sub = f"{path}.{key}" if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key) \
                else f"{path}[{json.dumps(key)}]"
            yield from leaves(v, sub, depth + 1)
    elif isinstance(value, list):
        for i, v in enumerate(value[:50]):
            yield from leaves(v, f"{path}[{i}]", depth + 1)
    else:
        yield path, value


def _depable(value, slot_is_id: bool) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return len(str(abs(value))) >= DEP_MIN_INT_DIGITS or (slot_is_id and abs(value) >= 1)
    if isinstance(value, str):
        if value == PLACEHOLDER:
            return False
        if _UUID.match(value) or _ULID.match(value) or looks_like_identifier(value):
            return True
        if _INT.match(value):
            return len(value.lstrip("-")) >= DEP_MIN_INT_DIGITS or slot_is_id
    return False


# --- the inventory -------------------------------------------------------------------

@dataclass
class _Endpoint:
    origin: str
    method: str
    template: str
    family: str
    pkinds: list[str]
    records: list[CaptureRecord] = field(default_factory=list)
    body: SchemaNode = field(default_factory=SchemaNode)
    query: dict[str, SchemaNode] = field(default_factory=dict)
    query_counts: dict[str, int] = field(default_factory=dict)
    path_params: list[SchemaNode] = field(default_factory=list)
    responses: dict[int, SchemaNode] = field(default_factory=dict)
    response_ctypes: dict[int, set] = field(default_factory=dict)
    headers: dict[str, list[str]] = field(default_factory=dict)
    req_ctypes: set = field(default_factory=set)
    req_fields: set = field(default_factory=set)
    resp_fields: set = field(default_factory=set)
    eid: str = ""

    def resource(self) -> str:
        """The collection a template names (``/a/{p1}/b/{p2}`` -> ``/a/{}/b``)."""
        t = self.template.rstrip("/")
        while t.endswith("}") and "/" in t:
            t = t.rsplit("/", 1)[0]
        return re.sub(r"\{p\d+\}", "{}", t)


def _field_names(value, depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > MAX_DEPTH:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(str(k))
            out |= _field_names(v, depth + 1)
    elif isinstance(value, list):
        for v in value[:50]:
            out |= _field_names(v, depth + 1)
    return out


def _mine_js(records: list[CaptureRecord]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for rec in records:
        if "javascript" not in (rec.res_ctype or "").lower() or not rec.res_body:
            continue
        origin = canonical_origin(rec.url) or ""
        for m in _JS_CALL.finditer(rec.res_body):
            method = (m.group(1) or m.group(2) or "").upper() or None
            key = (origin, method, m.group(3))
            seen.setdefault(key, {"origin": origin, "path": m.group(3), "method": method,
                                  "source": "js", "observed": False})
    return list(seen.values())


def synthesize(records: list[CaptureRecord], *, title: str = "disco inventory",
               captures: list[str] | None = None, quarantined: int = 0) -> dict:
    """The inventory (an OpenAPI 3.1 document) for ``records``."""
    http = sorted((r for r in records if r.kind == "http" and r.status is not None
                   and not is_static(r)), key=lambda r: r.t)
    keys = sorted({(canonical_origin(r.url) or "", urlsplit(r.url).path or "/") for r in http})
    data_values = frozenset(str(v) for r in http
                            for _jp, v in leaves(parse_body(r.res_body, r.res_ctype))
                            if isinstance(v, str) and 0 < len(v) <= 200)
    templates = template_paths(keys, data_values)
    eps: dict[tuple, _Endpoint] = {}
    rec_ep: list[tuple[CaptureRecord, _Endpoint, list[str]]] = []
    for rec in http:
        origin = canonical_origin(rec.url) or ""
        path = urlsplit(rec.url).path or "/"
        template, pkinds = templates[(origin, path)]
        fam = content_family(rec.req_ctype) if rec.req_body else "none"
        key = (origin, rec.method, template, fam)
        ep = eps.get(key)
        if ep is None:
            ep = eps[key] = _Endpoint(origin, rec.method, template, fam, pkinds,
                                      path_params=[SchemaNode() for _ in pkinds])
        ep.records.append(rec)
        values = [s for s, k in zip([s for s in path.split("/") if s],
                                    _segment_kinds_of(path, template)) if k]
        for node, val in zip(ep.path_params, values):
            node.add(int(val) if _INT.match(val) else val)
        rec_ep.append((rec, ep, values))
        for name, val in parse_qsl(urlsplit(rec.url).query, keep_blank_values=True):
            ep.query.setdefault(name, SchemaNode()).add(val)
            ep.query_counts[name] = ep.query_counts.get(name, 0) + 1
        body = parse_body(rec.req_body, rec.req_ctype)
        if body is not None and not rec.req_truncated:
            ep.body.add(body)
            ep.req_fields |= _field_names(body)
        if rec.req_ctype:
            ep.req_ctypes.add(rec.req_ctype.split(";", 1)[0].strip())
        res = parse_body(rec.res_body, rec.res_ctype)
        node = ep.responses.setdefault(rec.status, SchemaNode())
        ep.response_ctypes.setdefault(rec.status, set()).add(
            (rec.res_ctype or "").split(";", 1)[0].strip())
        if res is not None and not rec.res_truncated:
            node.add(res)
            ep.resp_fields |= _field_names(res)
        for name, val in rec.req_headers.items():
            if name not in _IGNORED_HEADERS:
                ep.headers.setdefault(name, []).append(val)
    ordered = sorted(eps.values(), key=lambda e: (e.origin, e.template, e.method, e.family))
    for i, ep in enumerate(ordered, 1):
        ep.eid = f"ep_{i:03d}"
    deps = _dependencies(rec_ep)
    by_resource: dict[str, set] = defaultdict(set)
    for ep in ordered:
        by_resource[ep.resource()] |= ep.req_fields
    paths: dict[str, dict] = {}
    origins = sorted({ep.origin for ep in ordered})
    for ep in ordered:
        op = _operation(ep, deps.get(ep.eid, []), by_resource[ep.resource()])
        item = paths.setdefault(ep.template, {})
        method = ep.method.lower()
        if method in item:                       # the same template on another origin
            method = f"x-{method}-{ep.eid}"
        item[method] = op
    return {"openapi": "3.1.0",
            "info": {"title": title, "version": "1"},
            "servers": [{"url": o} for o in origins],
            "paths": paths,
            "x-disco": {"captures": list(captures or []), "records": len(records),
                        "endpoint_records": len(http), "quarantined": quarantined,
                        "endpoints": len(ordered), "candidates": _mine_js(records)}}


def _segment_kinds_of(path: str, template: str) -> list[bool]:
    tparts = [s for s in template.split("/") if s]
    return [t.startswith("{p") for t in tparts]


def _dependencies(rec_ep) -> dict[str, list[dict]]:
    """Producer -> consumer edges (see the module docstring), per consumer id."""
    produced: dict = {}                # value -> (endpoint, jsonpath), latest wins
    edges: dict[tuple, dict] = {}
    for rec, ep, path_values in rec_ep:
        slots: list[tuple[str, object, bool]] = []
        for i, val in enumerate(path_values, 1):
            slots.append((f"path.p{i}", int(val) if _INT.match(val) else val, True))
        for name, val in parse_qsl(urlsplit(rec.url).query, keep_blank_values=True):
            slots.append((f"query.{name}", val, name.lower().endswith("id")))
        body = parse_body(rec.req_body, rec.req_ctype)
        if body is not None:
            for jp, val in leaves(body):
                key = jp.rsplit(".", 1)[-1].lower()
                slots.append((f"body.{jp}", val, key == "id" or key.endswith(("_id", "id"))))
        for target, val, is_id in slots:
            if not _depable(val, is_id):
                continue
            src = produced.get(str(val))
            if src is None or src[0] is ep:
                continue
            k = (src[0].eid, ep.eid, src[1], target)
            edge = edges.setdefault(k, {"producer": src[0].eid, "extract": src[1],
                                        "target": target, "count": 0})
            edge["count"] += 1
        res = parse_body(rec.res_body, rec.res_ctype)
        if res is not None:
            for jp, val in leaves(res):
                if _depable(val, True):
                    produced[str(val)] = (ep, _generalise(jp))
    out: dict[str, list[dict]] = defaultdict(list)
    for (_p, consumer, _x, _t), edge in sorted(edges.items()):
        out[consumer].append(edge)
    return out


def _generalise(jsonpath: str) -> str:
    """``$[3].id`` -> ``$[0].id``: an extraction names a shape, not one list index."""
    return re.sub(r"\[\d+\]", "[0]", jsonpath)


def _operation(ep: _Endpoint, deps: list[dict], resource_req_fields: set) -> dict:
    n = len(ep.records)
    params = []
    for i, (kind, node) in enumerate(zip(ep.pkinds, ep.path_params), 1):
        schema = node.schema()
        schema["x-kind"] = kind
        params.append({"name": f"p{i}", "in": "path", "required": True, "schema": schema})
    for name, node in sorted(ep.query.items()):
        params.append({"name": name, "in": "query",
                       "required": ep.query_counts[name] == n, "schema": node.schema()})
    headers = {}
    for name, vals in sorted(ep.headers.items()):
        if is_sensitive_name(name) or PLACEHOLDER in vals:
            headers[name] = {"class": "session"}
        elif len(set(vals)) == 1 and len(vals) == n:
            headers[name] = {"class": "static", "value": vals[0]}
        else:
            headers[name] = {"class": "varies"}
    session = any(h["class"] == "session" for h in headers.values())
    unauth_ok = any(r.status < 400 and not any(
        is_sensitive_name(k) or v == PLACEHOLDER for k, v in r.req_headers.items())
        for r in ep.records)
    auth = "none" if not session else ("optional" if unauth_ok else "required")
    op: dict = {"operationId": ep.eid, "parameters": params,
                "responses": {}}
    if ep.body.samples:
        ctype = sorted(ep.req_ctypes)[0] if ep.req_ctypes else "application/octet-stream"
        op["requestBody"] = {"content": {ctype: {"schema": ep.body.schema()}}}
    for status, node in sorted(ep.responses.items()):
        resp: dict = {"description": "observed"}
        ctypes = sorted(c for c in ep.response_ctypes.get(status, ()) if c)
        if node.samples and ctypes:
            resp["content"] = {ctypes[0]: {"schema": node.schema()}}
        op["responses"][str(status)] = resp
    lat = [r.latency_ms for r in ep.records if r.latency_ms is not None]
    resp_only = sorted(ep.resp_fields - resource_req_fields) if ep.body.samples else []
    op["x-disco"] = {
        "origin": ep.origin, "method": ep.method, "content_type_family": ep.family,
        "observed": True, "samples": n,
        "actions": sorted({r.action_id for r in ep.records if r.action_id})[:50],
        "profiles": sorted({r.profile for r in ep.records if r.profile}),
        "statuses": sorted({r.status for r in ep.records}),
        "headers": headers, "auth": auth, "dependencies": deps,
        "response_only_fields": resp_only,
        "latency_ms": {"p50": int(median(lat)), "max": max(lat)} if lat else None,
    }
    return op


def endpoints(inventory: dict):
    """``(template, method, operation)`` for every operation of an inventory, in order."""
    for template, item in (inventory.get("paths") or {}).items():
        for key, op in item.items():
            if isinstance(op, dict) and "x-disco" in op:
                yield template, op["x-disco"].get("method", key.upper()), op
