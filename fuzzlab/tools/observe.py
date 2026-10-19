"""Discovery observations as trace events (FR-AUD-28, `core.trace`).

The importers turn a crawl into store points; this module records, alongside, what the
crawl actually observed -- one event per spider row and per disco capture record --
so the data-flow diagram is built from evidence, not from the points derived from it.
Every event cites its source (``ref``: the spider table and row id, or the capture
record's position) and carries only what the source holds, redacted (`trace.safe_ref`):
method, URL, status, error, the parameter *names* and locations, the initiating page,
a redirect's target, the auth profile name. Never a header value or a body value.

Keys are stable per source (``<source tag>:<table>:<row>``, the tag a digest of the
source file's resolved path), so importing the same crawl into the same run twice adds
nothing. Without an active recorder (`trace.active`) nothing is done.

A disco run's events are built by `emit_capture_record` and `emit_disco_action` (with
`disco_tag` and `DiscoActionLines`, the one reader of ``actions.jsonl``) for both the
import (`observe_disco`) and the live trace of a capture (`disco.livetrace`, FR-CRAWL-30):
the same keys and bodies (FR-AUD-29). Refused hosts come from both layers that refuse:
the capture proxy's stats and the browser guard's count in ``explore.json`` (BUG-0524).

When the spider DB records it (FR-CRAWL-29), a page's event carries the time its load
began (``seen_at``) as ``t`` and the page whose load queued it (``found_from``, path only)
as ``referer``; a captured request's event carries the time it was captured. A DB from
before FR-CRAWL-29 leaves both unknown: ``t`` None (first/last seen unknown), no
``referer``; a page the crawl queued itself (the start URL, a well-known file) has no
``referer``. Never guessed (from row order, depth or another row's time).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from fuzzlab.core import trace
from fuzzlab.core.urls import canonical_origin

#: Spider ``discovered_requests.source`` values whose request never reached the server:
#: the browser made it inside the tool's write-blocking window and it was aborted.
NOT_SENT_SOURCES = frozenset({"dry-submit", "reveal-blocked"})


def _tag(path) -> str:
    return hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest()[:10]


def _query_params(url: str) -> list[list[str]]:
    return [[n, "query"] for n, _v in parse_qsl(urlsplit(url).query,
                                                keep_blank_values=True)]


def _body_params(ctype: str | None, body: str | None) -> list[list[str]]:
    """The names of a request body's fields (top level), never their values."""
    if not body:
        return []
    media = (ctype or "").split(";", 1)[0].strip().lower()
    try:
        if media == "application/json" or media.endswith("+json"):
            doc = json.loads(body)
            return [[str(k), "json"] for k in doc] if isinstance(doc, dict) else []
        if media == "application/x-www-form-urlencoded":
            return [[n, "body"] for n, _v in parse_qsl(body, keep_blank_values=True)]
    except (ValueError, TypeError):
        return []
    return []


def _path(url: str | None) -> str | None:
    if not url:
        return None
    ref = trace.safe_ref(url)
    parts = urlsplit(ref)
    return (parts.path or "/") + (f"#{parts.fragment}" if parts.fragment else "")


def _column(row, name):
    """``row[name]``, or None when the DB predates the column (FR-CRAWL-29)."""
    return row[name] if name in row.keys() else None


def _seen(row):
    """The row's ``seen_at`` as an event time, None when unknown."""
    t = _column(row, "seen_at")
    try:
        return None if t is None else float(t)
    except (TypeError, ValueError):
        return None


def observe_spider(spider_db) -> int:
    """Events for a spider DB's pages and captured requests; returns how many."""
    if trace.active() is None:
        return 0
    tag = f"spider:{_tag(spider_db)}"
    src = sqlite3.connect(str(spider_db))
    src.row_factory = sqlite3.Row
    n = 0
    try:
        try:
            pages = src.execute("SELECT rowid AS rid, * FROM discovered_pages "
                                "ORDER BY rowid").fetchall()
        except sqlite3.Error:
            pages = []
        for row in pages:
            url = row["url"]
            origin = canonical_origin(url)
            via = row["source"] if "source" in row.keys() else "link"
            kind = "observe.exchange" if via == "xhr" else "observe.page"
            # status 0: the spider's load got no response it kept (a failed load, or a
            # landing on another origin it withheld) -- never a reply (BUG-0515)
            status = row["status_code"] or None
            trace.emit(kind, {
                "src": "spider", "by": "crawler",
                "ref": f"discovered_pages row {row['rid']}",
                "method": "GET", "url": trace.safe_ref(url), "origin": origin,
                "status": status, "via": via, "params": _query_params(url),
                "outcome": "response" if status is not None
                else "no response recorded (status 0)",
                "referer": _path(_column(row, "found_from")),
                "order": row["rid"]}, key=f"{tag}:page:{row['rid']}", scope="spider",
                t=_seen(row))
            n += 1
        try:
            reqs = src.execute("SELECT * FROM discovered_requests ORDER BY id").fetchall()
        except sqlite3.Error:
            reqs = []
        for row in reqs:
            url = row["url"]
            source = row["source"]
            trace.emit("observe.exchange", {
                "src": "spider", "ref": f"discovered_requests id {row['id']}",
                "method": (row["method"] or "GET").upper(), "url": trace.safe_ref(url),
                "origin": canonical_origin(url), "ctype": row["content_type"],
                "via": source, "referer": _path(row["page_url"]),
                "delivery": ("blocked by the tool's write window: never reached the "
                             "server") if source in NOT_SENT_SOURCES else "sent",
                "params": _query_params(url) + _body_params(row["content_type"],
                                                            row["body_json"])},
                key=f"{tag}:request:{row['id']}", scope="spider", t=_seen(row))
            n += 1
    finally:
        src.close()
    return n


def disco_tag(run_dir) -> str:
    """The key prefix of a disco run directory's events (its resolved path's digest)."""
    return f"disco:{_tag(run_dir)}"


def emit_capture_record(tag: str, i: int, rec) -> None:
    """The event for capture record ``i`` (its position among the well-formed records,
    `capture.CaptureTail`), with the active recorder. FR-AUD-29: the import and the live
    trace (`disco.livetrace`) both build it here."""
    origin = canonical_origin(rec.url)
    headers = {k.lower(): v for k, v in (rec.req_headers or {}).items()}
    res = {k.lower(): v for k, v in (rec.res_headers or {}).items()}
    params = _query_params(rec.url) + _body_params(rec.req_ctype, rec.req_body)
    status = rec.status
    trace.emit("observe.exchange", {
        "src": "capture", "ref": f"capture.jsonl record {i}",
        "method": (rec.method or "GET").upper(), "url": trace.safe_ref(rec.url),
        "origin": origin, "status": status, "error": rec.error,
        "outcome": ("response" if status is not None else
                    f"no response ({rec.error or 'unknown'})"),
        "ws": rec.ws_direction if rec.kind == "ws" else None,
        "redirect": trace.safe_ref(res.get("location", "")) or None,
        "referer": _path(headers.get("referer")), "profile": rec.profile,
        "action": rec.action_id, "ctype": rec.req_ctype,
        "latency_ms": rec.latency_ms, "params": params},
        key=f"{tag}:rec:{i}", scope=f"workflow:{rec.action_id}" if rec.action_id
        else "capture", t=rec.t)


def _action_doc(raw: bytes) -> dict | None:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) and "seq" in doc else None


class DiscoActionLines:
    """``actions.jsonl`` as ``(line number, action or None)``: the one reader of the
    explorer's log for the import and the live trace (FR-AUD-29). Every physical line is
    numbered -- blank and malformed ones too, as None -- lines split on ``\\n`` bytes only
    and each complete line decoded alone (`capture.JsonlTail`). ``read`` returns what was
    completed since the last read; a missing log reads as nothing."""

    def __init__(self, path):
        from fuzzlab.disco.capture import JsonlTail
        self._lines = JsonlTail(path)
        self.lineno = 0

    def read(self, final: bool = False) -> list[tuple[int, dict | None]]:
        try:
            lines = self._lines.read(final)
        except FileNotFoundError:
            return []
        out = []
        for raw in lines:
            self.lineno += 1
            out.append((self.lineno, _action_doc(raw)))
        return out


def emit_disco_action(tag: str, lineno: int, doc: dict, ids: dict) -> None:
    """The event for the action on line ``lineno`` of ``actions.jsonl``. Its workflow is
    the id its requests carry (BUG-0512): the log's own ``action_id``; in a log from
    before it, the id a record with the same number carries (``ids``,
    `_disco_action_ids`); last, for an old log no record matches, the explorer's own
    naming (kept and documented, FR-AUD-28)."""
    seq = doc.get("seq")
    action_id = doc.get("action_id") or (ids.get(seq) if isinstance(seq, int) else None) \
        or f"{'harvest' if doc.get('kind') == 'load' else 'act'}-{seq}"
    trace.emit("observe.action", {
        "seq": seq, "kind": doc.get("kind"),
        "label": str(doc.get("label") or "")[:60],
        "route": trace.safe_ref(doc.get("route") or ""),
        "url": trace.safe_ref(doc.get("url") or ""),
        "fields": [f[0] for f in doc.get("fields") or [] if f]},
        key=f"{tag}:action:line{lineno}",     # stable: the log is appended
        scope=f"workflow:{action_id}", t=None)


def _disco_action_ids(records) -> dict[int, str]:
    """``act-``/``nav-``/``harvest-`` share one counter: number -> the id records carry."""
    ids = {}
    for rec in records:
        prefix, _d, num = (rec.action_id or "").rpartition("-")
        if prefix and num.isdigit():
            ids[int(num)] = rec.action_id
    return ids


def _guard_hosts(run_dir: Path) -> dict:
    """``explore.json``'s ``explore.out_of_scope``: the hosts the browser's own guard
    refused (navguard, counted by hostname), or nothing when absent or malformed."""
    try:
        doc = json.loads((run_dir / "explore.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    explore = doc.get("explore") if isinstance(doc, dict) else None
    hosts = explore.get("out_of_scope") if isinstance(explore, dict) else None
    if not isinstance(hosts, dict):
        return {}
    return {str(h): n for h, n in hosts.items()
            if isinstance(n, int) and not isinstance(n, bool)}


def observe_disco(run_dir, records) -> int:
    """Events for a disco run: each capture record (``records``, as `read_capture`
    returned them, in file order), each explorer action, and each host the browser asked
    for that was refused -- by the capture proxy (its stats, ``<tag>:external:<host>``)
    or by the browser's own guard (``explore.json``, ``<tag>:guard:<host>``, BUG-0524).
    Returns how many."""
    if trace.active() is None:
        return 0
    run_dir = Path(run_dir)
    tag = disco_tag(run_dir)
    n = 0
    for i, rec in enumerate(records):
        emit_capture_record(tag, i, rec)
        n += 1
    ids = _disco_action_ids(records)
    for lineno, doc in DiscoActionLines(run_dir / "actions.jsonl").read(final=True):
        if doc is not None:
            emit_disco_action(tag, lineno, doc, ids)
            n += 1
    stats = run_dir / "capture.jsonl.stats.json"
    if stats.exists():
        try:
            blocked = json.loads(stats.read_text()).get("blocked") or {}
        except ValueError:
            blocked = {}
        for host, count in sorted(blocked.items()):
            trace.emit("observe.external", {"src": "capture", "host": str(host)[:200],
                                            "count": count},
                       key=f"{tag}:external:{host}", scope="capture", t=None)
            n += 1
    # its own key: one host refused by both layers is two events, never one dropped by
    # INSERT OR IGNORE; the reducer keeps both counts as a set, never their sum
    for host, count in sorted(_guard_hosts(run_dir).items()):
        trace.emit("observe.external", {"src": "browser-guard", "host": host[:200],
                                        "count": count},
                   key=f"{tag}:guard:{host}", scope="capture", t=None)
        n += 1
    return n
