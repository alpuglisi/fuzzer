"""The site tree: browse what the store recorded by origin and URL path (CC-UI-0500).

Like Burp's Site map or ZAP's Sites tree, over the shared store (FR-UI-500..505). Pure
functions over one store connection -- no FastAPI here; `web/sitetree_routes.py` serves
them. Read-only: every request runs inside one read transaction and writes nothing.

**Nodes** (FR-UI-500). A node key is a small JSON object the client sends back opaque:

- host ``{"o": canonical origin}`` -- the runs whose first ``target`` row has that origin
  (`core.runtarget.run_origins`; loopback aliases on one port are one host), or
  ``{"r": run id}`` for a run with no recorded origin (no target row, or one whose URL has
  no usable host) -- never inferred from ``run.config_hash`` (PA-0075);
- dir / route ``+ "s": [segment, ...]`` -- `segments` of the stored path: the document
  path split on ``/`` (``""`` is an index), and a SPA hash route (``#/search``) as one
  last segment, so routes are children of their document path;
- endpoint ``+ "m": METHOD`` (``""``: a finding whose method was not recorded);
- parameter ``+ "p": name, "l": location or null`` (``p == ""``: no parameter).

Under a parameter are its findings (each links to the finding page) and candidates.

**Paths.** Every source's path goes through `path_key` (the stored value before its first
``?``; ``None`` when it does not start with ``/``): an endpoint may be stored with its
form action's or captured request's raw query, which is never shown, searched or used for
identity. A pipeline candidate's path is `oracle.finding_url` of its evidence -- the
convention its finding is stored with (PA-0003).

**Never shown** (FR-UI-504): any value column (``parameter.example``, form entries,
candidate or finding evidence beyond the projected path/method/param/location/category),
any query string, a target's raw ``base_url``, run notes or config. Strings are returned
as data; the page renders them as text.

**Cost** (FR-UI-502): a constant number of statements per request. Dir nodes narrow
endpoint/page/finding rows by an index-usable range on the stored path; findings and
candidates are scanned per selected run (no path index -- see the index request in
CC-UI-0500). A node's whole child list is built once and cached against the store's
version fingerprint, so paging is linear overall.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

from fuzzlab.core.evidence import display_evidence, method_key, parse_evidence
from fuzzlab.core.oracle_status import (CHECKED, INCONCLUSIVE, NO_CONFIRMER, PENDING,
                                         SKIPPED_BUDGET)
from fuzzlab.core.runmode import to_category
from fuzzlab.core.runtarget import origin_of, run_target_rows
from fuzzlab.web.findingsview import SEVERITIES, derive_severity

# --- bounds (PA-0096(1): sizes are bounded before anything is allocated) ------------
PAGE_DEFAULT = 200
PAGE_MAX = 1000
FINDINGS_DEFAULT = 50
FINDINGS_MAX = 200
KEY_MAX_BYTES = 4096
KEY_MAX_SEGMENTS = 256
STR_MAX = 2048
FILTER_MAX_VALUES = 64
Q_MAX = 512
#: Distinct groups an endpoint-level query reads before it reports ``truncated``.
GROUP_CAP = 10_000
#: The child-list cache (G1/G10): entries, children per entry, children in total.
CACHE_ENTRIES = 8
CACHE_ENTRY_MAX = 60_000
CACHE_TOTAL_MAX = 100_000
#: Candidate projections kept (content-addressed, no raw evidence held).
PROJECTION_CACHE_MAX = 65_536
#: Run ids bound per ``IN`` list when JSON1 is unavailable.
RUN_CHUNK = 500
#: The id range a cursor may name (SQLite's INTEGER).
ID_MAX = 2 ** 63 - 1

#: The status vocabulary (FR-UI-501): ``confirmed`` is a finding row; the rest are
#: `candidate.oracle_status` values (`core.oracle_status`), NULL or unknown reading
#: ``unrecorded`` -- never ``checked``.
CONFIRMED = "confirmed"
UNRECORDED = "unrecorded"
CANDIDATE_STATUSES = (CHECKED, INCONCLUSIVE, PENDING, SKIPPED_BUDGET, NO_CONFIRMER)
STATUSES = (CONFIRMED, *CANDIDATE_STATUSES, UNRECORDED)

#: Where a row could not be placed (counted at its run's host; G2/G3).
PLACES = ("unplaced", "no_path", "unreadable", "error")
#: The exceptions a registered SQL function turns into the ``error`` sentinel -- a named
#: list, never a bare ``Exception`` (PA-0106(1)): ``urlsplit`` on a malformed netloc,
#: wrong types, bad text, deep JSON. Anything else propagates (a 500, not lost data).
SWALLOWED = (ValueError, TypeError, UnicodeError, RecursionError)
ERROR_KEY = "x:error"


class SiteTreeError(ValueError):
    """A malformed request (a node key, filter or cursor): HTTP 400."""


class NodeGone(LookupError):
    """The node no longer resolves (e.g. a run got its origin mid-run): HTTP 404."""


# --- the path convention (FR-UI-500) ------------------------------------------------

def path_key(stored) -> str | None:
    """The path a stored URL-path names: the text before its first ``?`` -- a textual
    split, never `to_path` (which reads ``//x/y`` as a host). ``None`` (unplaced) for a
    non-string or a value that does not start with ``/``; nothing is re-rooted."""
    if not isinstance(stored, str) or not stored.startswith("/"):
        return None
    return stored.partition("?")[0]


def segments(path: str) -> list[str]:
    """The node segments of a path: the document path split on ``/`` after its leading
    one (``/`` -> ``[""]``, ``/a/`` -> ``["a", ""]``), then the SPA hash route, if any, as
    one last segment starting with ``#`` (``/#/search`` -> ``["", "#/search"]``). A
    literal ``#`` never occurs in a stored document path, so a ``#`` segment is a route."""
    doc, sep, route = path.partition("#")
    out = doc[1:].split("/")
    if sep:
        out.append("#" + route)
    return out


def _doc_path(segs: tuple[str, ...]) -> str:
    """The stored path a node's segments name (``("a", "")`` -> ``/a/``; a route node
    -> its document path plus the route)."""
    if segs and segs[-1].startswith("#"):
        return "/" + "/".join(segs[:-1]) + segs[-1]
    return "/" + "/".join(segs)


def _succ(text: str) -> str:
    """The smallest string greater than every string starting with ``text``."""
    return text[:-1] + chr(ord(text[-1]) + 1)


# --- node keys and filters ----------------------------------------------------------

@dataclass(frozen=True)
class NodeKey:
    origin: str | None = None
    run: int | None = None
    segs: tuple[str, ...] | None = None        # None: the root
    method: str | None = None
    param: str | None = None
    has_param: bool = False
    loc: str | None = None

    @property
    def level(self) -> str:
        if self.segs is None:
            return "root"
        if self.has_param:
            return "param"
        if self.method is not None:
            return "endpoint"
        if not self.segs:
            return "host"
        return "route" if self.segs[-1].startswith("#") else "dir"

    def dump(self) -> str | None:
        """The opaque key string, or ``None`` when it would exceed the key bound."""
        if self.segs is None:
            return ""
        d: dict[str, Any] = {"o": self.origin} if self.origin is not None else {"r": self.run}
        if self.segs:
            d["s"] = list(self.segs)
        if self.method is not None:
            d["m"] = self.method
        if self.has_param:
            d["p"] = self.param
            d["l"] = self.loc
        text = json.dumps(d, separators=(",", ":"), ensure_ascii=False)
        if len(text.encode("utf-8")) > KEY_MAX_BYTES or len(self.segs) > KEY_MAX_SEGMENTS:
            return None
        return text

    def child(self, **kw) -> "NodeKey":
        base = dict(origin=self.origin, run=self.run, segs=self.segs, method=self.method,
                    param=self.param, has_param=self.has_param, loc=self.loc)
        base.update(kw)
        return NodeKey(**base)


ROOT = NodeKey()


def _bounded_str(value, what: str, limit: int = STR_MAX) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise SiteTreeError(f"bad {what}")
    try:
        value.encode("utf-8")            # a lone surrogate cannot be stored or bound
    except UnicodeEncodeError as exc:
        raise SiteTreeError(f"bad {what}") from exc
    return value


def check_id(value, what: str = "cursor") -> int:
    """A cursor id in SQLite's INTEGER range, or a `SiteTreeError` (never an
    OverflowError at the bind)."""
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ID_MAX:
        raise SiteTreeError(f"bad {what}")
    return value


def fold(text: str) -> str:
    """ASCII-only lower-casing -- exactly what SQLite's ``lower()`` does, so every path
    search, in SQL or in Python, folds the same way (FR-UI-501)."""
    return text.translate(_ASCII_LOWER)


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def parse_key(text: str | None) -> NodeKey:
    """A node key from its string, validated strictly (FR-UI-502, PA-0096): unknown
    fields, wrong types or oversized values are a `SiteTreeError`, never a guess."""
    if text is None or text == "":
        return ROOT
    if not isinstance(text, str) or len(text.encode("utf-8")) > KEY_MAX_BYTES:
        raise SiteTreeError("node key too long")
    try:
        d = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise SiteTreeError("node key is not JSON") from exc
    if not isinstance(d, dict) or set(d) - {"o", "r", "s", "m", "p", "l"}:
        raise SiteTreeError("bad node key")
    if ("o" in d) == ("r" in d):
        raise SiteTreeError("a node key names exactly one host")
    origin = run = None
    if "o" in d:
        origin = _bounded_str(d["o"], "origin")
        if origin_of(origin) != origin:
            raise SiteTreeError("origin is not canonical")
    else:
        run = d["r"]
        if not isinstance(run, int) or isinstance(run, bool) or run < 1:
            raise SiteTreeError("bad run id")
    segs_raw = d.get("s", [])
    if not isinstance(segs_raw, list) or len(segs_raw) > KEY_MAX_SEGMENTS:
        raise SiteTreeError("bad segments")
    segs = tuple(_bounded_str(s, "segment") for s in segs_raw)
    if any(s.startswith("#") for s in segs[:-1]):
        raise SiteTreeError("a route is always the last segment")
    method = None
    if "m" in d:
        method = _bounded_str(d["m"], "method", 32)
        if not segs or method != method.upper():
            raise SiteTreeError("bad endpoint key")
    has_param = "p" in d
    param = loc = None
    if has_param:
        if method is None:
            raise SiteTreeError("a parameter key needs an endpoint")
        param = _bounded_str(d["p"], "parameter")
        loc = d.get("l")
        if loc is not None:
            loc = _bounded_str(loc, "location", 64)
    elif "l" in d:
        raise SiteTreeError("a location needs a parameter")
    return NodeKey(origin, run, segs, method, param, has_param, loc)


@dataclass(frozen=True)
class Filters:
    """FR-UI-501. Values within one facet are OR'ed; facets are AND'ed."""
    runs: frozenset[int] | None = None
    categories: frozenset[str] = frozenset()
    severities: frozenset[str] = frozenset()
    statuses: frozenset[str] = frozenset()
    q: str = ""

    @property
    def items_only(self) -> bool:
        """Any item facet set: only findings and candidates count, and a node shows
        only when its subtree holds a matching one."""
        return bool(self.categories or self.severities or self.statuses)

    def cache_key(self) -> tuple:
        return (None if self.runs is None else tuple(sorted(self.runs)),
                tuple(sorted(self.categories)), tuple(sorted(self.severities)),
                tuple(sorted(self.statuses)), self.q)


def parse_filters(*, run=(), category=(), severity=(), status=(), q: str = "") -> Filters:
    """Validated filters from request values (each a list of strings)."""
    for name, values in (("run", run), ("category", category), ("severity", severity),
                         ("status", status)):
        if len(values) > FILTER_MAX_VALUES:
            raise SiteTreeError(f"too many {name} values")
    runs = None
    if run:
        try:
            runs = frozenset(int(v) for v in run)
        except (TypeError, ValueError) as exc:
            raise SiteTreeError("bad run id") from exc
        if any(r < 1 for r in runs):
            raise SiteTreeError("bad run id")
    cats = frozenset(_bounded_str(c, "category", 128) for c in category)
    sevs = frozenset(severity)
    if sevs - set(SEVERITIES):
        raise SiteTreeError("unknown severity")
    stats = frozenset(status)
    if stats - set(STATUSES):
        raise SiteTreeError("unknown status")
    if not isinstance(q, str) or len(q) > Q_MAX:
        raise SiteTreeError("search text too long")
    return Filters(runs, cats, sevs, stats, q)


# --- candidate projection (G3/G4) ---------------------------------------------------

_proj_lock = threading.Lock()
_proj_cache: "OrderedDict[tuple[bytes, int], tuple]" = OrderedDict()


def _evidence_view(evidence) -> tuple:
    """What a candidate's stored evidence says, content-addressed and cached (G4):
    ``(pipeline fields or None, category, is a dict, has a url key)``. Raw evidence is
    never kept, only this projection."""
    if not isinstance(evidence, (str, bytes)):
        return (None, None, False, False)
    raw = evidence.encode("utf-8") if isinstance(evidence, str) else evidence
    key = (hashlib.blake2b(raw, digest_size=16).digest(), len(raw))
    with _proj_lock:
        hit = _proj_cache.get(key)
        if hit is not None:
            _proj_cache.move_to_end(key)
            return hit
    view = _evidence_view_uncached(evidence)
    with _proj_lock:
        _proj_cache[key] = view
        while len(_proj_cache) > PROJECTION_CACHE_MAX:
            _proj_cache.popitem(last=False)
    return view


def _evidence_view_uncached(evidence) -> tuple:
    shown = display_evidence(evidence)
    cat = shown.get("category")
    cat = cat if isinstance(cat, str) else None
    ev = parse_evidence(evidence)
    pipeline = None
    if ev is not None:
        from fuzzlab.oracle.oracle import finding_url   # lazy: pulls in the strategies
        from fuzzlab.oracle.probe import Candidate
        loc = ev.get("location")
        loc = loc if isinstance(loc, str) else None
        path = finding_url(Candidate(url=ev["url"], param=ev["param"],
                                     location=loc or "query"))
        pipeline = (path_key(path), method_key(ev.get("method")), ev["param"], loc,
                    ev["category"])
    return (pipeline, cat, bool(shown) or _is_dict(evidence), "url" in shown)


def _is_dict(evidence) -> bool:
    try:
        return isinstance(json.loads(evidence), dict)
    except SWALLOWED:
        return False


def project_candidate(evidence, parameter_id, pa_name, pa_loc, ep_url,
                      ep_method) -> tuple:
    """``(place, path, method, param, location, category)`` of one candidate row (G3):
    FK (its parameter and endpoint resolve), pipeline (`parse_evidence` succeeds),
    ``unplaced`` (a parameter row whose endpoint does not resolve -- it had a location,
    now lost), ``no_path`` (an auditor dict without a url and no parameter), else
    ``unreadable``. ``place`` is ``ok`` for a placed row."""
    view = _evidence_view(evidence)
    cat = view[1]
    if parameter_id is not None and isinstance(ep_url, str):
        path = path_key(ep_url)
        if path is None:
            return ("unplaced", None, None, None, None, cat)
        return ("ok", path, method_key(ep_method), pa_name if isinstance(pa_name, str)
                else "", pa_loc if isinstance(pa_loc, str) else None, cat)
    if view[0] is not None:
        path, method, param, loc, pcat = view[0]
        if path is None:
            return ("unplaced", None, None, None, None, pcat)
        return ("ok", path, method, param, loc, pcat)
    if parameter_id is not None:          # its parameter row lost its endpoint
        return ("unplaced", None, None, None, None, cat)
    if view[2] and not view[3]:
        return ("no_path", None, None, None, None, cat)
    return ("unreadable", None, None, None, None, None)


def _pack(fields) -> str:
    """One projection as JSON: target-supplied strings may hold any character, so no
    separator is safe (code review)."""
    return json.dumps(list(fields), ensure_ascii=False)


_unpacked = threading.local()


def _unpack(packed: str, i: int):
    """Field ``i`` of a packed projection; the last one parsed is kept per thread,
    since SQL reads several fields of each row in turn."""
    if getattr(_unpacked, "key", None) != packed:
        _unpacked.key, _unpacked.value = packed, json.loads(packed)
    return _unpacked.value[i]


# --- registered SQL functions (G2: total by construction, named swallow list) -------

def _encodable(value) -> bool:
    if not isinstance(value, str):
        return True
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:            # a lone surrogate (a JSON ``\udXXX`` escape)
        return False


def _sql_cproj(evidence, parameter_id, pa_name, pa_loc, ep_url, ep_method):
    try:
        out = project_candidate(evidence, parameter_id, pa_name, pa_loc, ep_url, ep_method)
    except SWALLOWED:
        return _pack(("error", None, None, None, None, None))
    if not all(_encodable(f) for f in out):
        # SQLite cannot hold such a string: one stored row must not take the reader down
        # (PA-0500(2), code review re-check) -- it is unreadable, and counted
        return _pack(("unreadable", None, None, None, None, None))
    return _pack(out)


def _sql_pf(packed, i):
    if not isinstance(packed, str) or not isinstance(i, int):
        return None
    return _unpack(packed, i)


# Total by construction (type-checked inputs, string operations only): no swallow list.
def _sql_sev(vuln_class):
    return derive_severity(vuln_class if isinstance(vuln_class, str) else None)


def _sql_fcat(vuln_class):
    return to_category(vuln_class) if isinstance(vuln_class, str) else "unknown"


def _sql_path(stored):
    return path_key(stored)


def _sql_method(method, finding):
    """``method_key`` for endpoints, pages and candidates; a finding without a recorded
    method keeps ``""`` (never defaulted to GET: ML reads it as "any method")."""
    if finding and (method is None or method == ""):
        return ""
    return method_key(method)


def _child_function(segs: tuple[str, ...]):
    """``fl_child(path, method)`` for one node: ``"e:METHOD"`` (an endpoint at this
    node), ``"s:SEGMENT"`` (a child), ``"x:unplaced"`` (no path; host level only),
    ``"x:error"``, or NULL (not under this node)."""
    depth = len(segs)
    want = list(segs)

    def child(path, method):           # total by construction: str operations only
        if path is None:
            return "x:unplaced" if depth == 0 else None
        if not isinstance(path, str):
            return ERROR_KEY
        sg = segments(path)
        if len(sg) < depth or sg[:depth] != want:
            return None
        if len(sg) == depth:
            return "e:" + (method if isinstance(method, str) else "")
        return "s:" + sg[depth]
    return child


def register(conn: sqlite3.Connection, segs: tuple[str, ...] = ()) -> None:
    """Register the site tree's SQL functions on ``conn`` (per request)."""
    conn.create_function("fl_cproj", 6, _sql_cproj, deterministic=True)
    conn.create_function("fl_pf", 2, _sql_pf, deterministic=True)
    conn.create_function("fl_sev", 1, _sql_sev, deterministic=True)
    conn.create_function("fl_fcat", 1, _sql_fcat, deterministic=True)
    conn.create_function("fl_path", 1, _sql_path, deterministic=True)
    conn.create_function("fl_method", 2, _sql_method, deterministic=True)
    conn.create_function("fl_child", 2, _child_function(segs), deterministic=True)


# --- SQLite feature detection (G5, F14) ---------------------------------------------

_features: dict[str, bool] = {}


def _feature(conn: sqlite3.Connection, name: str) -> bool:
    if name not in _features:
        if name == "materialized":
            _features[name] = sqlite3.sqlite_version_info >= (3, 35, 0)
        elif name == "json1":
            try:
                conn.execute("SELECT 1 FROM json_each('[]')").fetchall()
                _features[name] = True
            except sqlite3.OperationalError:
                _features[name] = False
    return _features[name]


def _mat(conn) -> str:
    return "MATERIALIZED " if _feature(conn, "materialized") else ""


def _runs_clause(conn, col: str, runs: list[int]) -> tuple[str, list]:
    if not runs:
        return "0", []
    if _feature(conn, "json1"):
        return f"{col} IN (SELECT value FROM json_each(?))", [json.dumps(runs)]
    parts, args = [], []
    for i in range(0, len(runs), RUN_CHUNK):
        chunk = runs[i:i + RUN_CHUNK]
        parts.append(f"{col} IN ({','.join('?' * len(chunk))})")
        args.extend(chunk)
    return "(" + " OR ".join(parts) + ")", args


def _in(col: str, values) -> tuple[str, list]:
    values = sorted(values)
    return f"{col} IN ({','.join('?' * len(values))})", values


# --- statement accounting (the scale test's hooks; F6) ------------------------------

class Counters:
    """Operation counts of the current request, for `tests/test_web_sitetree_scale.py`
    (never wall-clock; PA-0095(2)). ``fetched`` counts rows read into Python."""

    def __init__(self):
        self.fetched = 0

    def rows(self, cursor):
        for row in cursor:
            self.fetched += 1
            yield row


_counters = threading.local()


def _fetch(cursor):
    c = getattr(_counters, "current", None)
    return c.rows(cursor) if c is not None else cursor


def counting(counters: Counters | None) -> None:
    """Install (or clear) the counters for this thread's next requests."""
    _counters.current = counters


# --- the run set of a host ----------------------------------------------------------

@dataclass
class _Runs:
    meta: dict[int, dict]                       # run id -> {tool, started_at}
    origin_of: dict[int, str | None]            # run id -> origin (None: unreadable)


def _load_runs(conn, filters: Filters) -> _Runs:
    meta = {}
    for r in _fetch(conn.execute("SELECT id, tool, started_at FROM run ORDER BY id")):
        rid = int(r[0])
        if filters.runs is None or rid in filters.runs:
            meta[rid] = {"tool": r[1], "started_at": r[2]}
    targets = run_target_rows(conn, meta.keys())
    return _Runs(meta, {rid: origin_of(row["base_url"]) for rid, row in targets.items()})


def _host_runs(runs: _Runs, key: NodeKey) -> list[int]:
    if key.origin is not None:
        out = sorted(r for r, o in runs.origin_of.items() if o == key.origin)
    else:
        out = [key.run] if key.run in runs.meta and runs.origin_of.get(key.run) is None \
            else []
    if not out:
        raise NodeGone("this host no longer resolves under the current filters")
    return out


def _host_label(runs: _Runs, rid: int) -> str:
    m = runs.meta.get(rid, {})
    why = "origin unreadable" if rid in runs.origin_of else "origin not recorded"
    return f"run #{rid} · {m.get('tool') or '?'} — {why}"


# --- the leaf query (dir / route / host nodes) --------------------------------------

def _ranges(key: NodeKey, after: str | None) -> list[tuple[str, str] | str] | None:
    """The stored-path ranges holding a node's leaves (F5): ``None`` for a host (no
    narrowing), else exact values and ``[lo, hi)`` ranges, each a superset that
    ``fl_child`` judges exactly. Stored ``?``-suffixed variants fall in the same
    ranges (``[P?, P@)``)."""
    segs = key.segs or ()
    if not segs:
        return None
    d = _doc_path(segs)
    out: list = [d, (d + "?", d + "@")]
    if not segs[-1].startswith("#"):
        lo = d + "/"
        if after and after.startswith("s:") and not after[2:].startswith("#"):
            lo = max(lo, d + "/" + after[2:])          # cursor narrowing (F5)
        out.append((lo, _succ(d + "/")))
        out.append((d + "#", _succ(d + "#")))
    return out


def _range_sql(col: str, ranges) -> tuple[list[str], list[list]]:
    """One condition per range (each an index-usable SELECT branch)."""
    if ranges is None:
        return ["1"], [[]]
    conds, args = [], []
    for r in ranges:
        if isinstance(r, str):
            conds.append(f"{col} = ?")
            args.append([r])
        else:
            conds.append(f"({col} >= ? AND {col} < ?)")
            args.append(list(r))
    return conds, args


def _needle(key: NodeKey) -> str | None:
    """A substring every pipeline candidate under the node carries in its evidence
    JSON: its document path without the leading ``/`` -- only when JSON-safe ASCII
    (``json.dumps`` would escape anything else). ``None``: no pre-filter."""
    segs = key.segs or ()
    if not segs:
        return None
    text = _doc_path(segs)[1:]
    if not text or any(ord(ch) < 0x20 or ord(ch) > 0x7e or ch in '"\\' for ch in text):
        return None
    return text


#: Evidence whose URL holds an escaped tab, CR or LF (which `urlsplit` strips from the
#: path) passes the pre-filter whatever the needle (code review).
_LOOSE_ESCAPES = ("instr(c.evidence, char(92) || 't') > 0 OR instr(c.evidence, char(92) "
                  "|| 'r') > 0 OR instr(c.evidence, char(92) || 'n') > 0")


def _loose(needle: str | None) -> str:
    """The pre-filter for candidates without an endpoint row: a superset of those under
    the node (exactness is `fl_child`'s)."""
    if not needle:
        return "ep.url IS NULL"
    return f"ep.url IS NULL AND (instr(c.evidence, ?) > 0 OR {_LOOSE_ESCAPES})"


def _status_sql(col: str) -> str:
    known = ", ".join(f"'{s}'" for s in CANDIDATE_STATUSES)
    return f"CASE WHEN {col} IN ({known}) THEN {col} ELSE '{UNRECORDED}' END"


def _leaf_query(conn, key: NodeKey, runs: list[int], filters: Filters,
                after: str | None = None) -> tuple[str, list]:
    """``leaf(run_id, kind, k, path, status, sev, cat, item_id)`` for the node's runs:
    endpoints ``e``, pages ``g``, candidates ``c``, findings ``f``; ``k`` is the child
    key (`_child_function`). Filters are applied here (FR-UI-501)."""
    rng = _ranges(key, after)
    mat = _mat(conn)
    want_path = bool(filters.q)
    parts, args = [], []

    def runs_for(col):
        return _runs_clause(conn, col, runs)

    for table, kind in (("endpoint", "e"), ("page", "g")):
        if filters.items_only:
            break
        conds, cargs = _range_sql("url", rng)
        for cond, carg in zip(conds, cargs):
            rc, ra = runs_for("run_id")
            parts.append(
                f"SELECT run_id, '{kind}' AS kind, fl_child(fl_path(url), "
                f"fl_method(method, 0)) AS k, "
                f"{'fl_path(url)' if want_path else 'NULL'} AS path, NULL AS status, "
                f"NULL AS sev, NULL AS cat, id AS item_id FROM {table} "
                f"WHERE {rc} AND {cond}")
            args.extend(ra + carg)

    # candidates: project once (materialised), then key
    conds, cargs = _range_sql("ep.url", rng)
    rc, ra = runs_for("c.run_id")
    needle = _needle(key)
    loose = _loose(needle)
    cand_where = f"{rc} AND (({' OR '.join(conds)}) OR ({loose}))"
    cand_args = ra + [a for carg in cargs for a in carg] + ([needle] if needle else [])
    cand_cte = (
        f"cand AS {mat}(SELECT c.id, c.run_id, c.oracle_status, fl_cproj(c.evidence, "
        f"c.parameter_id, pa.name, pa.location, ep.url, ep.method) AS p "
        f"FROM candidate c LEFT JOIN parameter pa ON pa.id = c.parameter_id "
        f"LEFT JOIN endpoint ep ON ep.id = pa.endpoint_id WHERE {cand_where})")
    cand_select = (
        "SELECT run_id, 'c' AS kind, CASE fl_pf(p, 0) WHEN 'ok' THEN "
        "fl_child(fl_pf(p, 1), fl_pf(p, 2)) ELSE "
        + ("'x:' || fl_pf(p, 0)" if not (key.segs or ()) else "NULL") +
        f" END AS k, {'fl_pf(p, 1)' if want_path else 'NULL'} AS path, "
        f"{_status_sql('oracle_status')} AS status, NULL AS sev, fl_pf(p, 5) AS cat, "
        "id AS item_id FROM cand")
    parts.append(cand_select)

    conds, cargs = _range_sql("url", rng)
    for cond, carg in zip(conds, cargs):
        rc, ra = runs_for("run_id")
        parts.append(
            f"SELECT run_id, 'f' AS kind, fl_child(fl_path(url), fl_method(method, 1)) "
            f"AS k, {'fl_path(url)' if want_path else 'NULL'} AS path, "
            f"'{CONFIRMED}' AS status, fl_sev(vuln_class) AS sev, fl_fcat(vuln_class) "
            f"AS cat, id AS item_id FROM finding WHERE {rc} AND label = 1 AND {cond}")
        args.extend(ra + carg)

    where, wargs = _item_where(filters)
    sql = (f"WITH {cand_cte}, raw AS {mat}({' UNION ALL '.join(parts)}) "
           f"SELECT * FROM raw WHERE k IS NOT NULL{where}")
    return sql, cand_args + args + wargs


def _item_where(filters: Filters) -> tuple[str, list]:
    conds, args = [], []
    if filters.items_only:
        conds.append("kind IN ('c', 'f')")
    if filters.statuses:
        c, a = _in("status", filters.statuses)
        conds.append(c)
        args += a
    if filters.categories:
        c, a = _in("cat", filters.categories)
        conds.append(c)
        args += a
    if filters.severities:                      # findings only (F3)
        c, a = _in("sev", filters.severities)
        conds.append(c)
        args += a
    if filters.q:
        # problem rows (x: keys) carry no path and never match a search
        conds.append("instr(lower(path), lower(?)) > 0")
        args.append(filters.q)
    return ("".join(" AND " + c for c in conds), args)


# --- roll-ups ------------------------------------------------------------------------

def _empty_rollup() -> dict:
    return {"findings": 0, "by_severity": dict.fromkeys(SEVERITIES, 0), "by_category": {},
            "candidates": 0, "by_status": dict.fromkeys(STATUSES, 0), "last_run": None,
            "endpoints": 0, "problems": dict.fromkeys(PLACES, 0)}


def _add(roll: dict, kind: str, status, sev, cat, n: int, last_run) -> None:
    if last_run is not None and (roll["last_run"] is None or last_run > roll["last_run"]):
        roll["last_run"] = int(last_run)
    if kind == "f":
        roll["findings"] += n
        roll["by_severity"][sev if sev in roll["by_severity"] else "info"] += n
        roll["by_category"][cat or "unknown"] = roll["by_category"].get(cat or "unknown",
                                                                        0) + n
        roll["by_status"][CONFIRMED] += n
    elif kind == "c":
        roll["candidates"] += n
        roll["by_status"][status if status in roll["by_status"] else UNRECORDED] += n
    elif kind in ("e", "g"):
        roll["endpoints"] += n


def _merge(into: dict, other: dict) -> None:
    for k in ("findings", "candidates", "endpoints"):
        into[k] += other[k]
    for k in ("by_severity", "by_status", "problems", "by_category"):
        for kk, v in other[k].items():
            into[k][kk] = into[k].get(kk, 0) + v
    if other["last_run"] is not None and (into["last_run"] is None
                                          or other["last_run"] > into["last_run"]):
        into["last_run"] = other["last_run"]


# --- the child-list cache (G1, G10, G11) ---------------------------------------------

class _ChildCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._data: "OrderedDict[tuple, list]" = OrderedDict()
        self._total = 0
        self.enabled = True

    def get(self, key):
        if not self.enabled or key[-1] is None:
            return None
        with self._lock:
            hit = self._data.get(key)
            if hit is not None:
                self._data.move_to_end(key)
            return hit

    def put(self, key, entry: dict) -> None:
        """Keep ``{"children": [...], "truncated": bool}`` for ``key``."""
        size = len(entry["children"])
        if not self.enabled or key[-1] is None or size > CACHE_ENTRY_MAX:
            return
        with self._lock:
            old = self._data.pop(key, None)
            if old is not None:
                self._total -= len(old["children"])
            self._data[key] = entry
            self._total += size
            while self._data and (len(self._data) > CACHE_ENTRIES
                                  or self._total > CACHE_TOTAL_MAX):
                _k, gone = self._data.popitem(last=False)
                self._total -= len(gone["children"])

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._total = 0


child_cache = _ChildCache()


# --- the store's version fingerprint (F2, G6) ---------------------------------------

def store_version(path) -> str | None:
    """A fingerprint of the store with no SQLite at all: the store file's ``os.stat``
    (device, inode, size, mtime) and its WAL's size and 32-byte header (checkpoint
    sequence and salts); ``None`` when the store does not exist. A commit appends WAL
    frames (UPDATE-only ones too), a checkpoint rewrites the store file, a WAL restart
    changes the salts, and a store switch or copy changes the file. A reader opening
    the store creates an empty WAL, so a WAL shorter than its header counts as absent,
    and its inode and mtime are not used: reads never change the fingerprint (code
    review). Stated residual: in rollback-journal mode (only if WAL could not be set)
    an UPDATE inside one mtime tick that keeps the file size is not seen."""
    if path is None:            # no project open (FR-UI-458): no store, no fingerprint
        return None
    base = os.fspath(path)
    try:
        st = os.stat(base)
    except FileNotFoundError:
        return None
    parts = [f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}"]
    try:
        with open(base + "-wal", "rb") as fh:
            header = fh.read(32)
            size = os.fstat(fh.fileno()).st_size
        parts.append(f"{size}:{header.hex()}" if len(header) == 32 else "-")
    except FileNotFoundError:
        parts.append("-")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


# --- requests ------------------------------------------------------------------------

def _read(conn, fn: Callable[[], Any]):
    """Run ``fn`` inside one read transaction (F12): one snapshot per request."""
    if conn.in_transaction:
        conn.rollback()
    conn.execute("BEGIN")
    try:
        return fn()
    finally:
        conn.rollback()


def _check_limit(limit, default: int, maximum: int) -> int:
    if limit is None:
        return default
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= maximum:
        raise SiteTreeError(f"limit must be 1..{maximum}")
    return limit


def _page(items: list, after: str | None, limit: int, sort_key: str = "sort",
          truncated: bool = False) -> dict:
    """One page of a whole child list. ``truncated``: an endpoint's groups reached
    `GROUP_CAP`, so the list is partial -- said, never silent (code review), even when
    no group was read at all."""
    if after:
        items = [c for c in items if c[sort_key] > after]
    page = items[:limit]
    nxt = page[-1][sort_key] if len(items) > limit else None
    for c in page:
        c.pop(sort_key, None)
        c.pop("truncated", None)
    return {"children": page, "next": nxt, "truncated": truncated}


def children(conn, key: NodeKey, filters: Filters, *, after: str | None = None,
             limit: int | None = None, version: str | None = None) -> dict:
    """The children of ``key`` (FR-UI-500/502): ``{"children": [...], "next": cursor}``;
    for a parameter node, its findings and candidates (`items`). ``version`` is the
    store fingerprint taken **before** this request's snapshot (G11), the cache key."""
    limit = _check_limit(limit, PAGE_DEFAULT, PAGE_MAX)
    if after is not None:
        _bounded_str(after, "cursor")
    if key.level == "param":
        return items(conn, key, filters, before=after, limit=min(limit, FINDINGS_MAX))
    ck = (key.dump(), filters.cache_key(), version)
    cached = child_cache.get(ck)
    if cached is not None:
        return _page([dict(c) for c in cached["children"]], after, limit,
                     truncated=cached["truncated"])

    def build():
        register(conn, key.segs or ())
        runs = _load_runs(conn, filters)
        if key.level == "root":
            return _host_children(conn, runs, filters), False
        host_runs = _host_runs(runs, key)
        if key.level == "endpoint":
            data = _endpoint_rows(conn, key, host_runs, any_method=(key.method == ""))
            return _endpoint_groups(key, data, filters), data["truncated"]
        return _dir_children(conn, key, host_runs, filters, after), False
    built, truncated = _read(conn, build)
    if not after:
        child_cache.put(ck, {"children": [dict(c) for c in built], "truncated": truncated})
    return _page(built, after, limit, truncated=truncated)


def _item_cursor(text: str | None) -> tuple[int, str] | None:
    """An items cursor ``"<id>:<kind>"``: findings and candidates are two id spaces,
    so the order is (id descending, kind) and the cursor names both."""
    if text is None or text == "":
        return None
    sid, _sep, kind = _bounded_str(text, "cursor", 64).partition(":")
    if kind not in ("candidate", "finding"):
        raise SiteTreeError("bad cursor")
    try:
        return check_id(int(sid)), kind
    except ValueError as exc:
        raise SiteTreeError("bad cursor") from exc


def _after_cursor(item: dict, cur: tuple[int, str] | None) -> bool:
    return cur is None or item["id"] < cur[0] or (item["id"] == cur[0]
                                                  and item["kind"] > cur[1])


def _host_children(conn, runs: _Runs, filters: Filters) -> list[dict]:
    """Root's children: one node per canonical origin, and one per run without one."""
    if not runs.meta:
        return []
    sql, args = _leaf_query(conn, ROOT.child(segs=()), sorted(runs.meta), filters)
    per_run: dict[int, dict] = {}
    for rid, kind, k, status, sev, cat, n, last in _fetch(conn.execute(
            f"SELECT run_id, kind, k, status, sev, cat, COUNT(*), MAX(run_id) "
            f"FROM ({sql}) GROUP BY run_id, kind, k LIKE 'x:%', "
            f"CASE WHEN k LIKE 'x:%' THEN k END, status, sev, cat", args)):
        roll = per_run.setdefault(int(rid), _empty_rollup())
        if isinstance(k, str) and k.startswith("x:"):
            place = k[2:]
            roll["problems"][place if place in roll["problems"] else "error"] += n
        else:
            _add(roll, kind, status, sev, cat, n, last)
    hosts: dict[str, dict] = {}
    for rid, roll in sorted(per_run.items()):
        if not (roll["findings"] or roll["candidates"] or roll["endpoints"]
                or (not filters.items_only and not filters.q
                    and any(roll["problems"].values()))):
            continue
        origin = runs.origin_of.get(rid)
        if origin is not None:
            node = ROOT.child(origin=origin, segs=())
            label, sort = origin, "0:" + origin
        else:
            node = ROOT.child(run=rid, segs=())
            label, sort = _host_label(runs, rid), f"1:{rid:012d}"
        entry = hosts.setdefault(sort, {"key": node.dump(), "kind": "host",
                                        "label": label, "expandable": True,
                                        "rollup": _empty_rollup(), "sort": sort})
        _merge(entry["rollup"], roll)
    return [hosts[s] for s in sorted(hosts)]


def _dir_children(conn, key: NodeKey, runs: list[int], filters: Filters,
                  after: str | None) -> list[dict]:
    sql, args = _leaf_query(conn, key, runs, filters, after)
    out: dict[str, dict] = {}
    order: list[str] = []
    for k, kind, status, sev, cat, n, last in _fetch(conn.execute(
            f"SELECT k, kind, status, sev, cat, COUNT(*), MAX(run_id) FROM ({sql}) "
            f"WHERE k NOT LIKE 'x:%' GROUP BY k, kind, status, sev, cat ORDER BY k",
            args)):
        entry = out.get(k)
        if entry is None:
            entry = out[k] = _child_entry(key, k)
            order.append(k)
        _add(entry["rollup"], kind, status, sev, cat, n, last)
    return [out[k] for k in order]


def _child_entry(key: NodeKey, k: str) -> dict:
    segs = key.segs or ()
    if k.startswith("e:"):
        method = k[2:]
        node = key.child(method=method)
        path = _doc_path(segs)
        label = f"{method or '(method not recorded)'} {path}"
        kind = "endpoint"
    else:
        seg = k[2:]
        node = key.child(segs=segs + (seg,))
        kind = "route" if seg.startswith("#") else "dir"
        label = seg if seg else "/"
    dumped = node.dump()
    entry = {"key": dumped, "kind": kind, "label": label, "expandable": dumped is not None,
             "rollup": _empty_rollup(), "sort": k}
    if dumped is None:
        entry["label"] = label + " (too deep to browse here)"
    return entry


# --- endpoint level -------------------------------------------------------------------

def _endpoint_rows(conn, key: NodeKey, runs: list[int], any_method: bool) -> dict:
    """Everything recorded for one endpoint path (and method): parameter rows,
    candidate groups and finding groups, each capped at `GROUP_CAP` groups."""
    path = _doc_path(key.segs or ())
    method = key.method or ""
    truncated = False

    def capped(cursor):
        nonlocal truncated
        rows = []
        for r in _fetch(cursor):
            if len(rows) >= GROUP_CAP:
                truncated = True
                break
            rows.append(r)
        return rows

    rc, ra = _runs_clause(conn, "ep.run_id", runs)
    params = capped(conn.execute(
        f"SELECT ep.run_id, fl_method(ep.method, 0), pa.name, pa.location "
        f"FROM endpoint ep JOIN parameter pa ON pa.endpoint_id = ep.id "
        f"WHERE {rc} AND (ep.url = ? OR (ep.url >= ? AND ep.url < ?)) "
        f"GROUP BY ep.run_id, fl_method(ep.method, 0), pa.name, pa.location",
        ra + [path, path + "?", path + "@"]))

    rc, ra = _runs_clause(conn, "c.run_id", runs)
    needle = _needle(key)
    loose = _loose(needle)
    cands = capped(conn.execute(
        f"WITH cand AS {_mat(conn)}(SELECT c.id, c.run_id, c.oracle_status, "
        f"fl_cproj(c.evidence, c.parameter_id, pa.name, pa.location, ep.url, ep.method) "
        f"AS p FROM candidate c LEFT JOIN parameter pa ON pa.id = c.parameter_id "
        f"LEFT JOIN endpoint ep ON ep.id = pa.endpoint_id WHERE {rc} AND "
        f"(ep.url = ? OR (ep.url >= ? AND ep.url < ?) OR ({loose}))) "
        f"SELECT run_id, fl_pf(p, 2) m, fl_pf(p, 3) prm, fl_pf(p, 4) loc, "
        f"{_status_sql('oracle_status')} st, fl_pf(p, 5) cat, COUNT(*), MAX(run_id) "
        f"FROM cand WHERE fl_pf(p, 0) = 'ok' AND fl_pf(p, 1) = ? "
        f"GROUP BY run_id, m, prm, loc, st, cat",
        ra + [path, path + "?", path + "@"] + ([needle] if needle else []) + [path]))

    rc, ra = _runs_clause(conn, "run_id", runs)
    finds = capped(conn.execute(
        f"SELECT run_id, fl_method(method, 1) m, COALESCE(param, '') prm, vuln_class, "
        f"fl_sev(vuln_class), fl_fcat(vuln_class), COUNT(*), MAX(run_id) FROM finding "
        f"WHERE {rc} AND label = 1 AND (url = ? OR (url >= ? AND url < ?)) "
        f"GROUP BY run_id, m, prm, vuln_class",
        ra + [path, path + "?", path + "@"]))

    # the endpoint's own endpoint / page rows (count, last run) for its summary
    structure = (0, None)
    if method:
        parts, sargs = [], []
        for table in ("endpoint", "page"):
            rc, ra = _runs_clause(conn, "run_id", runs)
            parts.append(f"SELECT run_id, method FROM {table} WHERE {rc} AND "
                         f"(url = ? OR (url >= ? AND url < ?))")
            sargs += ra + [path, path + "?", path + "@"]
        row = next(iter(_fetch(conn.execute(
            f"SELECT COUNT(*), MAX(run_id) FROM ({' UNION ALL '.join(parts)}) "
            f"WHERE fl_method(method, 0) = ?", sargs + [method]))))
        structure = (int(row[0]), row[1])

    # every method's rows feed location resolution; only this endpoint's method makes
    # groups -- and the "(method not recorded)" endpoint has findings only (G8)
    params_m = [r for r in params if r[1] == method] if method else []
    cands_m = [r for r in cands if r[1] == method] if method else []
    finds = [r for r in finds if r[1] == method]
    return {"params": params, "params_m": params_m, "cands": cands, "cands_m": cands_m,
            "finds": finds, "structure": structure, "truncated": truncated,
            "locations": _Locations(cands, params)}


class _Locations:
    """Finding -> parameter location for one endpoint path (F8, G8), indexed once per
    request by ``(run, param)`` and memoised per finding key, so resolving every
    finding is linear in the rows read (PA-0095; it was a scan per finding)."""

    def __init__(self, cands, params):
        self.cands: dict[tuple, list] = {}
        self.params: dict[tuple, list] = {}
        for c in cands:              # (run, method, param, loc, status, cat, n, last)
            self.cands.setdefault((c[0], c[2] or ""), []).append((c[1], c[3], c[5]))
        for p in params:             # (run, method, name, location)
            loc = p[3] if isinstance(p[3], str) else None
            self.params.setdefault((p[0], p[2] or ""), []).append((p[1], loc))
        self._memo: dict[tuple, str | None] = {}
        self.steps = len(cands) + len(params)   # the scale test's operation count

    def resolve(self, run_id: int, param: str, vuln_class, method: str) -> str | None:
        """The unique location among the run's candidates at this path with the
        finding's method (any method when it has none), param and category
        (`to_category(vuln_class)`); if none match, the unique location among those
        candidates and the parameter rows without the category (parameter rows carry no
        category, and `to_category` is a lossy spelling map); else ``None``."""
        key = (run_id, param or "", vuln_class, method)
        if key in self._memo:
            return self._memo[key]
        cat = to_category(vuln_class) if isinstance(vuln_class, str) else None
        cands = self.cands.get((run_id, param or ""), [])
        params = self.params.get((run_id, param or ""), [])
        self.steps += 1 + len(cands) + len(params)
        first = {loc for m, loc, c in cands if (method == "" or m == method) and c == cat}
        if first:
            out = next(iter(first)) if len(first) == 1 else None
        else:
            second = {loc for m, loc, _c in cands if method == "" or m == method}
            second |= {loc for m, loc in params if method == "" or m == method}
            out = next(iter(second)) if len(second) == 1 else None
        self._memo[key] = out
        return out


def _endpoint_children(conn, key: NodeKey, runs: list[int], filters: Filters) -> list:
    data = _endpoint_rows(conn, key, runs, any_method=(key.method == ""))
    return _endpoint_groups(key, data, filters)


def _endpoint_groups(key: NodeKey, data: dict, filters: Filters) -> list:
    """An endpoint's parameter nodes from its rows (pure)."""
    if filters.q and fold(filters.q) not in fold(_doc_path(key.segs or ())):
        return []
    groups: dict[tuple, dict] = {}

    def group(param, loc):
        param = param or ""
        g = groups.get((param, loc))
        if g is None:
            node = key.child(param=param, has_param=True, loc=loc)
            dumped = node.dump()
            label = (param or "(no parameter)") + " · " + (loc or "location not recorded")
            g = groups[(param, loc)] = {
                "key": dumped, "kind": "param", "label": label, "param": param,
                "location": loc, "expandable": dumped is not None,
                "rollup": _empty_rollup(),
                "sort": json.dumps([param, loc is None, loc or ""], ensure_ascii=False)}
        return g

    if not filters.items_only:
        for rid, _m, name, loc in data["params_m"]:
            g = group(name, loc if isinstance(loc, str) else None)
            _add(g["rollup"], "e", None, None, None, 0, rid)
    for rid, _m, prm, loc, st, cat, n, last in data["cands_m"]:
        if not _item_ok(filters, "c", st, None, cat):
            continue
        _add(group(prm, loc)["rollup"], "c", st, None, cat, n, last)
    for rid, m, prm, vc, sev, cat, n, last in data["finds"]:
        if not _item_ok(filters, "f", CONFIRMED, sev, cat):
            continue
        loc = data["locations"].resolve(rid, prm, vc, m)
        _add(group(prm, loc)["rollup"], "f", CONFIRMED, sev, cat, n, last)
    out = sorted(groups.values(), key=lambda g: g["sort"])
    return out


def _item_ok(filters: Filters, kind: str, status, sev, cat) -> bool:
    if filters.statuses and status not in filters.statuses:
        return False
    if filters.categories and cat not in filters.categories:
        return False
    if filters.severities and (kind != "f" or sev not in filters.severities):
        return False
    return True


# --- parameter level: the items ------------------------------------------------------

def items(conn, key: NodeKey, filters: Filters, *, before: str | None = None,
          limit: int | None = None) -> dict:
    """A parameter node's findings and candidates, newest first, keyset-paged by
    ``(id, kind)`` (``before`` is the previous page's ``next``). Only identifiers,
    classes, statuses and runs -- never evidence."""
    limit = _check_limit(limit, FINDINGS_DEFAULT, FINDINGS_MAX)
    cur = _item_cursor(before)
    bound = None if cur is None else cur[0] + 1          # SQL: id <= cursor id

    def build():
        register(conn, key.segs or ())
        runs = _host_runs(_load_runs(conn, filters), key)
        if filters.q and fold(filters.q) not in fold(_doc_path(key.segs or ())):
            return {"children": [], "next": None, "truncated": False}
        data = _endpoint_rows(conn, key, runs, any_method=(key.method == ""))
        path = _doc_path(key.segs or ())
        out = []
        if not filters.statuses or CONFIRMED in filters.statuses:
            out.extend(f for f in _matching_findings(conn, key, runs, filters, path,
                                                     data, bound, limit + 2)
                       if _after_cursor(f, cur))
        if not filters.severities:
            out.extend(c for c in _matching_candidates(conn, key, runs, filters, path,
                                                       bound, limit + 2)
                       if _after_cursor(c, cur))
        out.sort(key=lambda it: (-it["id"], it["kind"]))
        page = out[:limit]
        nxt = f"{page[-1]['id']}:{page[-1]['kind']}" if len(out) > limit else None
        return {"children": page, "next": nxt, "truncated": data["truncated"]}
    return _read(conn, build)


def _matching_findings(conn, key, runs, filters, path, data, before, cap):
    rc, ra = _runs_clause(conn, "run_id", runs)
    sql = (f"SELECT id, run_id, vuln_class, confidence, created_at, fl_method(method, 1) "
           f"m, fl_sev(vuln_class) sev, fl_fcat(vuln_class) cat FROM finding "
           f"WHERE {rc} AND label = 1 AND (url = ? OR (url >= ? AND url < ?)) "
           f"AND COALESCE(param, '') = ?" + (" AND id < ?" if before else "")
           + " ORDER BY id DESC")
    args = ra + [path, path + "?", path + "@", key.param or ""] + \
        ([before] if before else [])
    found = []
    for fid, rid, vc, mech, created, m, sev, cat in _fetch(conn.execute(sql, args)):
        if m != key.method or not _item_ok(filters, "f", CONFIRMED, sev, cat):
            continue
        loc = data["locations"].resolve(rid, key.param or "", vc, m)
        if loc != key.loc:
            continue
        found.append({"kind": "finding", "id": int(fid), "run_id": int(rid),
                      "vuln_class": vc, "severity": sev, "category": cat,
                      "mechanism": mech, "created_at": created,
                      "href": f"/findings/{int(fid)}"})
        if len(found) >= cap:
            break
    return found


def _matching_candidates(conn, key, runs, filters, path, before, cap):
    rc, ra = _runs_clause(conn, "c.run_id", runs)
    needle = _needle(key)
    loose = _loose(needle)
    sql = (f"WITH cand AS {_mat(conn)}(SELECT c.id, c.run_id, c.oracle_status, "
           f"fl_cproj(c.evidence, c.parameter_id, pa.name, pa.location, ep.url, "
           f"ep.method) AS p FROM candidate c LEFT JOIN parameter pa ON pa.id = "
           f"c.parameter_id LEFT JOIN endpoint ep ON ep.id = pa.endpoint_id WHERE {rc} "
           f"AND (ep.url = ? OR (ep.url >= ? AND ep.url < ?) OR ({loose}))"
           + (" AND c.id < ?" if before else "") +
           f") SELECT id, run_id, {_status_sql('oracle_status')}, fl_pf(p, 5), "
           f"fl_pf(p, 2), fl_pf(p, 3), fl_pf(p, 4) FROM cand WHERE fl_pf(p, 0) = 'ok' "
           f"AND fl_pf(p, 1) = ? ORDER BY id DESC")
    args = ra + [path, path + "?", path + "@"] + ([needle] if needle else []) + \
        ([before] if before else []) + [path]
    found = []
    for cid, rid, st, cat, m, prm, loc in _fetch(conn.execute(sql, args)):
        if m != key.method or (prm or "") != (key.param or "") or loc != key.loc:
            continue
        if not _item_ok(filters, "c", st, None, cat):
            continue
        found.append({"kind": "candidate", "id": int(cid), "run_id": int(rid),
                      "category": cat, "status": st})
        if len(found) >= cap:
            break
    return found


# --- node summary (the detail pane) --------------------------------------------------

def summary(conn, key: NodeKey, filters: Filters, *, before: int | None = None,
            limit: int | None = None) -> dict:
    """The node's own roll-up and a page of the findings in its subtree, newest first
    (FR-UI-503), in one read transaction (F12). Findings carry their link to the finding
    page; no evidence."""
    limit = _check_limit(limit, FINDINGS_DEFAULT, FINDINGS_MAX)
    if before is not None:
        check_id(before, "before")
    if key.level == "root":
        raise SiteTreeError("select a host or a deeper node")

    def build():
        register(conn, key.segs or ())
        runs_all = _load_runs(conn, filters)
        runs = _host_runs(runs_all, key)
        roll = _empty_rollup()
        truncated = False
        if key.level in ("host", "dir", "route"):
            sql, args = _leaf_query(conn, key, runs, filters)
            for kind, k, status, sev, cat, n, last in _fetch(conn.execute(
                    f"SELECT kind, k, status, sev, cat, COUNT(*), MAX(run_id) "
                    f"FROM ({sql}) GROUP BY kind, k LIKE 'x:%', CASE WHEN k LIKE 'x:%' "
                    f"THEN k END, status, sev, cat", args)):
                if isinstance(k, str) and k.startswith("x:"):
                    place = k[2:]
                    roll["problems"][place if place in roll["problems"] else "error"] += n
                else:
                    _add(roll, kind, status, sev, cat, n, last)
            finds = _subtree_findings(conn, key, runs, filters, before, limit + 1)
        else:
            endpoint = key.child(param=None, has_param=False, loc=None)
            data = _endpoint_rows(conn, endpoint, runs, any_method=(key.method == ""))
            truncated = data["truncated"]
            entries = _endpoint_groups(endpoint, data, filters)
            for e in entries:
                if key.level == "endpoint" or (e["param"] == (key.param or "")
                                               and e["location"] == key.loc):
                    _merge(roll, e["rollup"])
            q_ok = not filters.q or fold(filters.q) in fold(_doc_path(key.segs))
            if key.level == "endpoint":
                n, last = data["structure"]
                if n and q_ok and not filters.items_only:
                    _add(roll, "e", None, None, None, n, last)
                finds = _subtree_findings(conn, key, runs, filters, before, limit + 1)
            elif not q_ok or (filters.statuses and CONFIRMED not in filters.statuses):
                finds = []
            else:
                finds = _matching_findings(conn, key, runs, filters, _doc_path(key.segs),
                                           data, before, limit + 1)
        nxt = str(finds[limit - 1]["id"]) if len(finds) > limit else None
        return {"node": _describe(key, runs_all), "rollup": roll,
                "findings": finds[:limit], "next": nxt, "truncated": truncated}
    return _read(conn, build)


def _subtree_findings(conn, key: NodeKey, runs, filters, before, cap) -> list[dict]:
    if filters.statuses and CONFIRMED not in filters.statuses:
        return []
    rng = _ranges(key, None)
    conds, cargs = _range_sql("url", rng)
    rc, ra = _runs_clause(conn, "run_id", runs)
    where_path = "(" + " OR ".join(conds) + ")"
    sql = (f"SELECT id, run_id, vuln_class, confidence, created_at, url, "
           f"fl_method(method, 1) m, COALESCE(param, '') prm, fl_sev(vuln_class) sev, "
           f"fl_fcat(vuln_class) cat, fl_child(fl_path(url), fl_method(method, 1)) k "
           f"FROM finding WHERE {rc} AND label = 1 AND {where_path}"
           + (" AND id < ?" if before else "") + " ORDER BY id DESC")
    args = ra + [a for c in cargs for a in c] + ([before] if before else [])
    out = []
    for fid, rid, vc, mech, created, url, m, prm, sev, cat, k in _fetch(
            conn.execute(sql, args)):
        if k is None or k.startswith("x:"):
            continue
        if key.level == "endpoint" and k != "e:" + (key.method or ""):
            continue
        if not _item_ok(filters, "f", CONFIRMED, sev, cat):
            continue
        path = path_key(url)
        if filters.q and fold(filters.q) not in fold(path or ""):
            continue
        out.append({"kind": "finding", "id": int(fid), "run_id": int(rid),
                    "vuln_class": vc, "severity": sev, "category": cat,
                    "mechanism": mech, "method": m or None, "path": path,
                    "param": prm, "created_at": created,
                    "href": f"/findings/{int(fid)}"})
        if len(out) >= cap:
            break
    return out


def _describe(key: NodeKey, runs: _Runs) -> dict:
    if key.origin is not None:
        host = key.origin
    else:
        host = _host_label(runs, key.run)
    d = {"key": key.dump(), "level": key.level, "host": host}
    if key.segs:
        d["path"] = _doc_path(key.segs)
    if key.method is not None:
        d["method"] = key.method or None
    if key.has_param:
        d["param"] = key.param
        d["location"] = key.loc
    return d


# --- facets ---------------------------------------------------------------------------

def facets(conn) -> dict:
    """Filter choices (FR-UI-501): runs (id, tool, start, host label), categories (the
    audit categories plus every finding's), severities and statuses."""
    def build():
        register(conn)
        runs = _load_runs(conn, Filters())
        out_runs = []
        for rid, m in sorted(runs.meta.items(), reverse=True):
            origin = runs.origin_of.get(rid)
            out_runs.append({"id": rid, "tool": m["tool"], "started_at": m["started_at"],
                             "host": origin if origin is not None
                             else _host_label(runs, rid)})
        cats = set(_known_categories())
        for (c,) in _fetch(conn.execute(
                "SELECT DISTINCT fl_fcat(vuln_class) FROM finding WHERE label = 1")):
            if c:
                cats.add(c)
        return {"runs": out_runs, "categories": sorted(cats),
                "severities": list(SEVERITIES), "statuses": list(STATUSES)}
    return _read(conn, build)


def _known_categories() -> list[str]:
    try:
        from fuzzlab.audit import known_categories
        return list(known_categories())
    except ImportError:
        return []


__all__ = ["NodeKey", "Filters", "SiteTreeError", "NodeGone", "parse_key", "parse_filters",
           "children", "items", "summary", "facets", "store_version", "path_key",
           "segments", "project_candidate", "child_cache", "Counters",
           "counting", "ROOT", "STATUSES"]
