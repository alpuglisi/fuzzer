"""The capture proxy's addon: the scope firewall and the one writer of ``capture.jsonl``.

Loaded by ``mitmdump -s`` (through `fuzzlab.disco.mitm`, so it runs in this
interpreter, with this package importable). Options:

* ``disco_scope`` -- comma-separated URLs; their canonical origins (scheme, host, port,
  `core.urls.origin_scope`) are the only places a request may go. **Empty refuses
  everything** (fail closed).
* ``disco_out`` -- the ``capture.jsonl`` path; ``disco_stats`` -- a JSON file of the
  refused requests per host (rewritten on each refusal and at shutdown).
* ``disco_profile`` -- the auth profile (``user_a``, ``anon``) stamped on every record.
* ``disco_keep_tag`` -- forward the ``x-disco-action`` header to the target (default
  off: the tag is read here and stripped, so the target never sees it).

**Scope is enforced where the request is made (PA-0123(1)).** A CONNECT to an origin
outside scope is killed before mitmproxy connects upstream (the launcher sets
``connection_strategy=lazy``), and every request is checked again on its own URL
(`core.urls.in_origin_scope`, the one predicate): the browser's launch arguments and
route guard are the other two layers, and none of the three trusts the others.

Hooks never block the event loop (PA-0102(3)): records are queued to one writer thread,
which appends and flushes each (PA-0012). A full queue drops the record and counts it
(``dropped`` in the stats) rather than stall the proxy.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from urllib.parse import urlsplit

from fuzzlab.core.urls import in_origin_scope, origin_scope
from fuzzlab.disco.capture import ACTION_HEADER, append_record, make_record

#: Records waiting for the writer; past this the proxy drops and counts.
QUEUE_MAX = 10_000
#: How long shutdown waits for the writer to drain.
DRAIN_TIMEOUT_S = 10.0

_STOP = object()


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
        if self._writer is not None:
            self._queue.put(_STOP)
            self._writer.join(DRAIN_TIMEOUT_S)
            self._writer = None
        self._write_stats()

    def _drain(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            try:
                if item == "stats":
                    self._write_stats()
                elif self.out:
                    append_record(self.out, item)
                    self.recorded += 1
            except OSError as exc:              # a full disk loses a record, loudly
                logging.error("disco recorder could not write: %s", exc)

    def _enqueue(self, item) -> None:
        self.start()             # a script loaded after start-up never sees `running`
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            self.dropped += 1

    def _write_stats(self) -> None:
        if not self.stats_path:
            return
        doc = {"blocked": dict(sorted(self.blocked.items())), "recorded": self.recorded,
               "dropped": self.dropped}
        tmp = f"{self.stats_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, sort_keys=True)
        os.replace(tmp, self.stats_path)

    # --- scope -----------------------------------------------------------------------
    def in_scope(self, url: str) -> bool:
        return in_origin_scope(url, self.origins)

    def _refuse(self, flow, url: str) -> None:
        host = urlsplit(url).hostname or "?"
        self.blocked[host] = self.blocked.get(host, 0) + 1
        flow.kill()
        self._enqueue("stats")

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

    def response(self, flow) -> None:
        req, res = flow.request, flow.response
        if not self.in_scope(req.url):             # a refused flow is never recorded
            return
        start, end = req.timestamp_start, res.timestamp_end or time.time()
        self._enqueue(make_record(
            kind="http", t=start or time.time(), action_id=flow.metadata.get("disco_action"),
            method=req.method, url=req.url, req_headers=req.headers,
            req_body=req.get_content(strict=False), status=res.status_code,
            res_headers=res.headers, res_body=res.get_content(strict=False),
            latency_ms=int((end - start) * 1000) if start else None, profile=self.profile))

    def error(self, flow) -> None:
        req = flow.request
        if req is None or flow.response is not None or not self.in_scope(req.url):
            return
        err = getattr(flow, "error", None)
        if err is not None and "killed" in str(getattr(err, "msg", "")).lower():
            return                                   # our own refusal, already counted
        self._enqueue(make_record(
            kind="http", t=req.timestamp_start or time.time(),
            action_id=flow.metadata.get("disco_action"), method=req.method, url=req.url,
            req_headers=req.headers, req_body=req.get_content(strict=False),
            error=type(err).__name__ if err is not None else "error", profile=self.profile))

    def websocket_message(self, flow) -> None:
        req = flow.request
        if not self.in_scope(req.url):
            return
        msg = flow.websocket.messages[-1]
        self._enqueue(make_record(
            kind="ws", t=getattr(msg, "timestamp", None) or time.time(),
            action_id=flow.metadata.get("disco_action"), method="WS", url=req.url,
            req_headers=req.headers, req_body=bytes(msg.content or b""),
            ws_direction="client" if msg.from_client else "server", profile=self.profile))


addons = [Recorder()]
