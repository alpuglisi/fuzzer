"""The capture proxy's addon: the scope firewall and the one writer of ``capture.jsonl``.

Loaded by ``mitmdump -s`` (through `fuzzlab.disco.mitm`, so it runs in this
interpreter, with this package importable). Options:

* ``disco_scope`` -- comma-separated URLs; their canonical origins (scheme, host, port,
  `core.urls.origin_scope`) are the only places a request may go. **Empty refuses
  everything** (fail closed).
* ``disco_out`` -- the ``capture.jsonl`` path; ``disco_stats`` -- a JSON file of the
  refused requests per host, the records written and every loss (rewritten after a
  refusal and at shutdown).
* ``disco_profile`` -- the auth profile (``user_a``, ``anon``) stamped on every record.
* ``disco_keep_tag`` -- forward the ``x-disco-action`` header to the target (default
  off: the tag is read here and stripped, so the target never sees it).

**Scope is enforced where the request is made (PA-0123(1)).** A CONNECT to an origin
outside scope is killed before mitmproxy connects upstream (the launcher sets
``connection_strategy=lazy``), and every request is checked again on its own URL
(`core.urls.in_origin_scope`, the one predicate): the browser's launch arguments and
route guard are the other two layers, and none of the three trusts the others.

**Hooks never block the event loop (PA-0102(3), BUG-0548).** The loop carries every
browser request, so a hook only checks scope and takes the exchange
(`capture.snapshot`: references to the header pairs and the bodies as sent, in time that
does not depend on the bodies). The writer thread does all the work: decoding each body
under a ceiling (SP-60), redaction, the record, its JSON, the append and flush of each
record (PA-0012). That work still holds the GIL, so mitmdump's process switches
threads every `SWITCH_INTERVAL_S`, not CPython's 5 ms: the loop never waits longer for
it (measured, BUG-0548). A request asks the target only for codings that decoding can
bound (`bodyread.advertise`; Chromium asks for ``zstd`` too, measured), so no body is
lost to a coding the writer cannot decode.

**The queue is bounded by records and by bytes, with backpressure; every loss is
counted** (``stats``):
- an exchange that does not fit (past `QUEUE_MAX_BYTES` held, or `QUEUE_MAX` records)
  **waits in line**: its hook returns an awaitable, which mitmproxy awaits, so that
  flow -- and, to keep the records in order, every exchange after it -- is held back
  while the loop runs on (``waited``). The browser is paced to the writer; nothing is
  lost. The line is data, moved by every offer and every waiter, so a waiter never
  resumed holds no one back;
- one that still does not fit after `BACKPRESSURE_WAIT_S` is queued without its bodies
  (``omitted.backlog``): its record is written, with no body, marked truncated; if even
  that does not fit it is dropped (``dropped``);
- a body over `capture.MAX_CAPTURE_BODY_BYTES` is never held (``omitted.too_large``),
  and one the writer cannot decode whole is recorded without it
  (``omitted.undecodable``);
- a record that cannot be built or written is logged and ``dropped``, as is a waiting
  exchange whose flow is cancelled; at shutdown the line is handed to the writer (its
  exchanges are complete: only the browser was held back);
- ``queued`` is what was not yet written when the stats were written (in the queue or
  in line): at shutdown, after `DRAIN_TIMEOUT_S`, records never written.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import sys
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from fuzzlab.core.bodyread import advertise
from fuzzlab.core.urls import in_origin_scope, origin_scope
from fuzzlab.disco.capture import (ACTION_HEADER, OMIT_REASONS, HeldExchange, append_record,
                                   build_record, snapshot)

#: Records waiting for the writer, at most.
QUEUE_MAX = 10_000
#: Bytes the waiting exchanges may hold (URLs, header pairs, bodies as sent), at most:
#: how far the writer may fall behind the browser before the browser is held back.
QUEUE_MAX_BYTES = 32 << 20
#: How long an exchange may wait for room before it is queued without its bodies.
BACKPRESSURE_WAIT_S = 30.0
#: How often a waiting exchange looks for room.
BACKPRESSURE_POLL_S = 0.005
#: How long shutdown waits for the writer to drain. `proxyproc` gives mitmdump's stop
#: more than this (`proxyproc.STOP_GRACE_S`), so the drain is never cut by a kill.
DRAIN_TIMEOUT_S = 30.0
#: The proxy process's GIL switch interval (``sys.setswitchinterval``, set in `running`:
#: mitmdump's process only). The writer's work holds the GIL, and at CPython's default
#: 5 ms the loop waits up to that long for it at each wake-up. Measured (BUG-0548, 1500
#: requests, 64 KiB gzip JSON): loop lag median 6.1 -> 2.2 ms, p99 58.6 -> 22.5 ms, page
#: 76.7 -> 96.4 requests/s.
SWITCH_INTERVAL_S = 0.001

_STOP = object()
_STATS = object()


class _Waiting:
    """An exchange in line for the queue: ``state`` is ``waiting``, ``queued`` (handed to
    the writer, whole or without its bodies, or dropped and counted) or ``cancelled``."""
    __slots__ = ("ex", "deadline", "state")

    def __init__(self, ex: HeldExchange, deadline: float):
        self.ex, self.deadline, self.state = ex, deadline, "waiting"


def parse_scope(text: str) -> frozenset[str]:
    """The origins named by a comma-separated list of URLs (blank items ignored)."""
    return origin_scope(*[u.strip() for u in (text or "").split(",") if u.strip()])


class Recorder:
    """The addon. ``origins`` / ``out`` / ``stats`` / ``keep_tag`` are set from the
    options by `configure`; tests set them directly and call the hooks with fakes."""

    def __init__(self) -> None:
        self.origins: frozenset[str] = frozenset()
        self.out: str | None = None
        self.stats_path: str | None = None
        self.keep_tag = False
        self.profile: str | None = None
        self.blocked: dict[str, int] = {}
        self.recorded = 0
        self.dropped = 0
        self.waited = 0
        self.omitted: dict[str, int] = dict.fromkeys(OMIT_REASONS, 0)
        self.queued_bytes = 0
        self._lock = threading.Lock()           # counters, queued_bytes, the turns
        self._stats_lock = threading.Lock()     # one writer of the stats file at a time
        self._stats_due = False
        self._waiting: deque[_Waiting] = deque()  # the line, oldest first
        self._queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self._writer: threading.Thread | None = None

    # --- mitmproxy wiring ------------------------------------------------------------
    def load(self, loader) -> None:
        loader.add_option("disco_scope", str, "", "comma-separated URLs whose origins "
                          "are in scope; empty refuses everything")
        loader.add_option("disco_out", str, "", "capture.jsonl path")
        loader.add_option("disco_stats", str, "", "refusal stats JSON path")
        loader.add_option("disco_keep_tag", bool, False, "forward x-disco-action")
        loader.add_option("disco_profile", str, "", "auth profile stamped on records")

    def configure(self, updated) -> None:
        from mitmproxy import ctx
        opts = ctx.options
        self.origins = parse_scope(opts.disco_scope)
        self.out = opts.disco_out or None
        self.stats_path = opts.disco_stats or None
        self.keep_tag = bool(opts.disco_keep_tag)
        self.profile = opts.disco_profile or None

    def running(self) -> None:
        sys.setswitchinterval(SWITCH_INTERVAL_S)    # mitmdump's process: see the constant
        self.start()

    def done(self) -> None:
        self.stop()

    # --- the writer ----------------------------------------------------------------
    def start(self) -> None:
        if self._writer is None or not self._writer.is_alive():
            self._writer = threading.Thread(target=self._drain, name="disco-writer",
                                            daemon=True)
            self._writer.start()

    def stop(self) -> None:
        """Let the writer drain (`DRAIN_TIMEOUT_S` in all), then write the stats: what it
        did not write by then is ``queued`` in them."""
        if self._writer is not None:
            deadline = time.monotonic() + DRAIN_TIMEOUT_S
            self._flush_line(deadline)
            try:
                self._queue.put(_STOP, timeout=max(0.0, deadline - time.monotonic()))
            except queue.Full:
                logging.error("disco recorder: the writer did not drain at shutdown")
            self._writer.join(max(0.0, deadline - time.monotonic()))
            if self._writer.is_alive():
                logging.error("disco recorder: %d records unwritten at shutdown",
                              self._queue.qsize())
            self._writer = None
        self._write_stats()

    def _drain(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            if item is not _STATS:
                self._write(item)
            if self._stats_due:
                self._stats_due = False
                self._write_stats_logged()

    def _write(self, ex: HeldExchange) -> None:
        """Build and append one record; every failure is contained and counted
        (PA-0086(2)): the writer outlives any one exchange."""
        try:
            rec, undecodable = build_record(ex)
            with self._lock:
                self.omitted["undecodable"] += undecodable
            if self.out:
                append_record(self.out, rec)
                with self._lock:
                    self.recorded += 1
        except OSError as exc:                  # a full disk loses a record, loudly
            logging.error("disco recorder could not write: %s", exc)
            self._count_drop()
        except Exception as exc:                # a record that cannot be built
            logging.error("disco recorder could not build a record: %s",
                          type(exc).__name__)
            self._count_drop()
        finally:
            with self._lock:
                self.queued_bytes -= ex.size

    def _count_drop(self) -> None:
        with self._lock:
            self.dropped += 1

    # --- the queue: bounded, with backpressure (all under self._lock) ---------------
    def _fits(self, ex: HeldExchange) -> bool:
        return self.queued_bytes + ex.size <= QUEUE_MAX_BYTES and not self._queue.full()

    def _put(self, ex: HeldExchange) -> None:
        self._queue.put_nowait(ex)               # never Full: `_fits` held under the lock
        self.queued_bytes += ex.size
        for reason in ex.omissions():
            self.omitted[reason] += 1

    def _put_bare_or_drop(self, ex: HeldExchange) -> None:
        bare = ex.without_bodies("backlog")
        if self._fits(bare):
            self._put(bare)
        else:
            self.dropped += 1

    def _pump(self) -> None:
        """Queue the waiting exchanges, oldest first, while the oldest fits; one past its
        deadline (or one that could never fit whole) goes without its bodies, or is
        dropped. The line is data, not its waiters' coroutines: any waiter, and every
        offer, moves it, so a waiter that is never resumed holds no one back."""
        while self._waiting:
            w = self._waiting[0]
            if w.state == "waiting":
                if self._fits(w.ex):
                    self._put(w.ex)
                elif time.monotonic() >= w.deadline or w.ex.size > QUEUE_MAX_BYTES:
                    self._put_bare_or_drop(w.ex)
                else:
                    return
                w.state = "queued"
            self._waiting.popleft()

    def _offer(self, ex: HeldExchange):
        """Queue ``ex`` for the writer. When it fits and nothing waits, now (returns
        None). Otherwise it joins the line and an awaitable is returned that finishes
        once it is queued (`BACKPRESSURE_WAIT_S` at most): mitmproxy awaits it, holding
        back this flow, never the loop."""
        self.start()             # a script loaded after start-up never sees `running`
        with self._lock:
            self._pump()
            if not self._waiting:
                if self._fits(ex):
                    self._put(ex)
                    return None
                if ex.size > QUEUE_MAX_BYTES:
                    self._put_bare_or_drop(ex)   # it could never fit whole
                    return None
            w = _Waiting(ex, time.monotonic() + BACKPRESSURE_WAIT_S)
            self._waiting.append(w)
            self.waited += 1
        return self._wait_in_line(w)

    async def _wait_in_line(self, w: "_Waiting") -> None:
        try:
            while True:
                with self._lock:
                    self._pump()
                    if w.state != "waiting":
                        return
                await asyncio.sleep(BACKPRESSURE_POLL_S)
        except asyncio.CancelledError:
            with self._lock:
                if w.state == "waiting":         # never queued: lost, counted
                    w.state = "cancelled"
                    self.dropped += 1
            raise

    def _flush_line(self, deadline: float) -> None:
        """At shutdown: the waiting exchanges are complete (only the browser was held
        back), so each goes to the writer, waiting for room until ``deadline``."""
        with self._lock:
            line = [w for w in self._waiting if w.state == "waiting"]
            for w in line:
                w.state = "queued"
            self._waiting.clear()
        for w in line:
            try:
                self._queue.put(w.ex, timeout=max(0.0, deadline - time.monotonic()))
            except queue.Full:
                self._count_drop()
                continue
            with self._lock:
                self.queued_bytes += w.ex.size
                for reason in w.ex.omissions():
                    self.omitted[reason] += 1

    def _request_stats(self) -> None:
        """Have the writer rewrite the stats file. A full queue only defers it: the flag
        is read after the writer's next item, and `stop` writes them anyway."""
        self.start()
        if self._stats_due:                       # one request pending is enough
            return
        self._stats_due = True
        try:
            self._queue.put_nowait(_STATS)
        except queue.Full:
            pass

    def stats(self) -> dict:
        with self._lock:
            waiting = sum(1 for w in self._waiting if w.state == "waiting")
            return {"blocked": dict(sorted(self.blocked.items())), "recorded": self.recorded,
                    "dropped": self.dropped, "omitted": dict(self.omitted),
                    "waited": self.waited, "queued": self._queue.qsize() + waiting}

    def _write_stats_logged(self) -> None:
        try:
            self._write_stats()
        except OSError as exc:
            logging.error("disco recorder could not write its stats: %s", exc)

    def _write_stats(self) -> None:
        if not self.stats_path:
            return
        doc = self.stats()
        with self._stats_lock:
            tmp = f"{self.stats_path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, sort_keys=True)
            os.replace(tmp, self.stats_path)

    # --- scope -----------------------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        return in_origin_scope(url, self.origins)

    def _refuse(self, flow, url: str) -> None:
        host = urlsplit(url).hostname or "?"
        with self._lock:
            self.blocked[host] = self.blocked.get(host, 0) + 1
        flow.kill()
        self._request_stats()

    # --- hooks -----------------------------------------------------------------------
    def http_connect(self, flow) -> None:
        """A tunnel names a host and port, not a scheme: the Playwright driver tunnels
        plain ``http`` too (measured: a CONNECT to an ``http`` lab origin). It is opened
        when ``host:port`` is in scope under either scheme; every request inside it is
        then checked on its real origin by `request`."""
        req = flow.request
        hostport = f"{req.host}:{req.port}"
        if not (self.in_scope(f"http://{hostport}/") or self.in_scope(f"https://{hostport}/")):
            self._refuse(flow, f"https://{hostport}/")

    def request(self, flow) -> None:
        url = flow.request.url                 # built from the connection's host/port
        if not self.in_scope(url):
            self._refuse(flow, url)
            return
        headers = flow.request.headers
        tag = headers.get(ACTION_HEADER)
        flow.metadata["disco_action"] = tag
        if tag is not None and not self.keep_tag:
            del headers[ACTION_HEADER]
        advertise(headers)                     # only codings the writer decodes bounded

    def response(self, flow):
        req, res = flow.request, flow.response
        url = req.url
        if not self.in_scope(url):                 # a refused flow is never recorded
            return None
        start, end = req.timestamp_start, res.timestamp_end or time.time()
        return self._offer(snapshot(
            kind="http", t=start or time.time(), action_id=flow.metadata.get("disco_action"),
            method=req.method, url=url, req_headers=req.headers, req_body=req.raw_content,
            status=res.status_code, res_headers=res.headers, res_body=res.raw_content,
            latency_ms=int((end - start) * 1000) if start else None, profile=self.profile))

    def error(self, flow):
        req = flow.request
        if req is None or flow.response is not None or not self.in_scope(req.url):
            return None
        err = getattr(flow, "error", None)
        if err is not None and "killed" in str(getattr(err, "msg", "")).lower():
            return None                              # our own refusal, already counted
        return self._offer(snapshot(
            kind="http", t=req.timestamp_start or time.time(),
            action_id=flow.metadata.get("disco_action"), method=req.method, url=req.url,
            req_headers=req.headers, req_body=req.raw_content,
            error=type(err).__name__ if err is not None else "error", profile=self.profile))

    def websocket_message(self, flow):
        req = flow.request
        if not self.in_scope(req.url):
            return None
        msg = flow.websocket.messages[-1]
        return self._offer(snapshot(
            kind="ws", t=getattr(msg, "timestamp", None) or time.time(),
            action_id=flow.metadata.get("disco_action"), method="WS", url=req.url,
            req_headers=req.headers, req_body=msg.content or None, coded=False,
            ws_direction="client" if msg.from_client else "server", profile=self.profile))


addons = [Recorder()]
