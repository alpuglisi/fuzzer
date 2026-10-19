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


def observe_disco(run_dir, records) -> int:
    """Events for a disco run: each capture record (``records``, as `read_capture`
    returned them, in file order), each explorer action, and each host the browser
    asked for that the scope refused. Returns how many."""
    if trace.active() is None:
        return 0
    run_dir = Path(run_dir)
    tag = f"disco:{_tag(run_dir)}"
    n = 0
    for i, rec in enumerate(records):
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
        n += 1
    actions = run_dir / "actions.jsonl"
    if actions.exists():
        # an action's workflow is the id its requests carry (BUG-0512): the log's own
        # ``action_id``, or, in a log from before it, the id a record carries with the
        # same number (``act-``/``nav-``/``harvest-`` share one counter)
        ids = {}
        for rec in records:
            prefix, _d, num = (rec.action_id or "").rpartition("-")
            if prefix and num.isdigit():
                ids[int(num)] = rec.action_id
        with open(actions, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                try:
                    doc = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(doc, dict) or "seq" not in doc:
                    continue
                seq = doc.get("seq")
                action_id = doc.get("action_id") or ids.get(seq) or \
                    f"{'harvest' if doc.get('kind') == 'load' else 'act'}-{seq}"
                trace.emit("observe.action", {
                    "seq": doc.get("seq"), "kind": doc.get("kind"),
                    "label": str(doc.get("label") or "")[:60],
                    "route": trace.safe_ref(doc.get("route") or ""),
                    "url": trace.safe_ref(doc.get("url") or ""),
                    "fields": [f[0] for f in doc.get("fields") or [] if f]},
                    key=f"{tag}:action:line{lineno}",     # stable: the log is appended
                    scope=f"workflow:{action_id}", t=None)
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
    return n
