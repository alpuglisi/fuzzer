"""Has an M6 page gone quiet: nothing left that could still run its script (SP-105).

The M6 browser executor waits up to ``SETTLE_MS`` after ``load`` for the sentinel,
because a sink can fire after ``load`` (BUG-0126: Juice Shop's search renders after its
own API call). A payload that does not fire used to wait that whole window, every
time: on bWAPP's ground truth 126 browser observations took 600 s of a 621 s run
(FR-FUZZ-650's measurement, CC-FUZZ-0650).

After ``load``, a document's script runs again only from something it is waiting
for: a timer, a request's answer, an animation frame or idle callback, a running
animation's events, a stream's message (WebSocket, EventSource) or a worker's message.
`PageQuiet` ends the wait early only when **none** of those is pending, in every frame,
for `QUIET_MS` in a row:

* no request in flight -- counted by SP-40's `netquiet.Inflight`, the one tracker; its
  last start or end restarts the quiet period;
* no timer due before the wait's own deadline, no interval, no animation frame, no idle
  callback and no running animation -- read from a small tracker every document gets
  before its own script (`TRACKER_JS`, an init script that wraps the timer functions;
  a timer due after the deadline is one the full wait would not have seen either);
* no WebSocket, EventSource or worker on the page at all (a pushed message may come at
  any time: such a page keeps the full wait).

It fails closed: a frame whose tracker cannot be read (an error page, a document that
runs no script, a frame being replaced) is "not quiet", and the wait runs as before.
A long-poll, which SP-40 never waits for, is not waited for here either (SP-40's
decision for every settle; its residual is recorded in FR-FUZZ-651).
"""

from __future__ import annotations

import time
from typing import Callable

from fuzzlab.tools.netquiet import STREAMING_TYPES, Inflight

#: How long a page must stay quiet before the wait ends early. Every sink measured
#: fired inside an activity (a timer, a request's answer), never after a quiet gap
#: (FR-FUZZ-650's timeline); the period only has to outlast the gap between one task
#: and the work it starts.
QUIET_MS = 500

#: The tracker's global name in each document (non-enumerable, read-only).
TRACKER_KEY = "__fuzzlab_quiet__"

#: Wraps a document's timer functions before its own script runs; ``globalThis[KEY]
#: (horizonMs)`` answers what is still pending. Ids are shared by timeouts and
#: intervals, so either clear forgets both. A string handler cannot be wrapped and is
#: pending until it is due. A timeout more than a second overdue has run.
TRACKER_JS = """(() => {
  const KEY = "%s";
  const g = globalThis;
  if (Object.prototype.hasOwnProperty.call(g, KEY)) return;
  const now = () => performance.now();
  const timeouts = new Map(), intervals = new Set(), frames = new Set(), idles = new Set();
  const st = g.setTimeout, ct = g.clearTimeout, si = g.setInterval, ci = g.clearInterval;
  const forget = (id) => { timeouts.delete(id); intervals.delete(id); };
  g.setTimeout = function setTimeout(handler, delay, ...rest) {
    let id;
    const run = typeof handler === "function"
      ? function () { timeouts.delete(id); return handler.apply(this, arguments); }
      : handler;
    id = st.call(g, run, delay, ...rest);
    timeouts.set(id, now() + Math.max(0, Number(delay) || 0));
    return id;
  };
  g.clearTimeout = function clearTimeout(id) { forget(id); return ct.call(g, id); };
  g.setInterval = function setInterval(handler, delay, ...rest) {
    const id = si.call(g, handler, delay, ...rest);
    intervals.add(id);
    return id;
  };
  g.clearInterval = function clearInterval(id) { forget(id); return ci.call(g, id); };
  const wrapCallbacks = (req, cancel, live) => {
    const r = g[req], c = g[cancel];
    if (typeof r !== "function") return;
    g[req] = function (cb, ...rest) {
      let id;
      id = r.call(g, function () { live.delete(id); return cb.apply(this, arguments); },
                  ...rest);
      live.add(id);
      return id;
    };
    if (typeof c === "function") {
      g[cancel] = function (id) { live.delete(id); return c.call(g, id); };
    }
  };
  wrapCallbacks("requestAnimationFrame", "cancelAnimationFrame", frames);
  wrapCallbacks("requestIdleCallback", "cancelIdleCallback", idles);
  Object.defineProperty(g, KEY, {enumerable: false, configurable: false, writable: false,
    value: (horizon) => {
      const t = now();
      let due = 0;
      for (const [id, at] of timeouts) {
        if (at < t - 1000) timeouts.delete(id);
        else if (at <= t + horizon) due += 1;
      }
      let animations = 0;
      try {
        if (g.document && g.document.getAnimations) {
          animations = g.document.getAnimations()
            .filter((a) => a.playState === "running").length;
        }
      } catch (e) { animations = -1; }
      return {due, intervals: intervals.size, frames: frames.size, idle: idles.size,
              animations};
    }});
})();""" % TRACKER_KEY

_READ_JS = ("([key, horizon]) => { const f = globalThis[key];"
            " return typeof f === 'function' ? f(horizon) : null; }")


class PageQuiet:
    """The quiet state of one M6 page, installed before its first navigation.

    ``install`` adds the tracker to every document of ``context`` and attaches SP-40's
    `Inflight` and the stream and worker listeners to ``page``. ``settled(deadline)``
    is polled by the wait: true once the page has been quiet for `QUIET_MS`. ``error``
    is the Playwright error class: a read that fails with it is "not quiet"."""

    def __init__(self, error: type[BaseException] = Exception, *,
                 clock: Callable[[], float] = time.monotonic, quiet_ms: int = QUIET_MS):
        self._error = error
        self._clock = clock
        self._quiet = quiet_ms / 1000
        self._since: float | None = None
        self.streams = 0                 # WebSockets / EventSources the page opened
        self.workers = 0
        self.inflight: Inflight | None = None
        #: why the page last read as not quiet (measurement and the trace)
        self.reason: str | None = "not read"
        #: when the wait first found the page settled (`time.monotonic()`), if it did
        self.settled_at: float | None = None

    def install(self, context, page) -> None:
        context.add_init_script(TRACKER_JS)
        self.inflight = Inflight(page, clock=self._clock)
        page.on("websocket", self._stream)
        page.on("request", self._request)
        page.on("worker", self._worker)

    def _stream(self, *_a) -> None:
        self.streams += 1

    def _worker(self, *_a) -> None:
        self.workers += 1

    def _request(self, request) -> None:
        if getattr(request, "resource_type", None) in STREAMING_TYPES:
            self.streams += 1

    def busy(self, page, horizon_s: float) -> str | None:
        """Why ``page`` is not quiet now (``None``: it is), for a wait ending in
        ``horizon_s`` seconds."""
        if self.streams:
            return "a stream (WebSocket or EventSource)"
        if self.workers:
            return "a worker"
        if self.inflight is None:
            return "not installed"
        if self.inflight.n:
            return "a request in flight"
        horizon = max(0, int(horizon_s * 1000))
        try:
            frames = list(page.frames)
            for frame in frames:
                state = frame.evaluate(_READ_JS, [TRACKER_KEY, horizon])
                if not isinstance(state, dict):
                    return "a frame without the tracker"
                for key, what in (("due", "a timer due"), ("intervals", "an interval"),
                                  ("frames", "an animation frame"),
                                  ("idle", "an idle callback"),
                                  ("animations", "a running animation")):
                    if state.get(key) != 0:
                        return what
        except self._error:
            return "a frame could not be read"
        return None

    def settled(self, page, deadline: float) -> bool:
        """Polled by the wait: true once ``page`` has been quiet for `QUIET_MS` (and
        no request started or ended in that time)."""
        now = self._clock()
        self.reason = self.busy(page, deadline - now)
        if self.reason is not None:
            self._since = None
            return False
        if self._since is None:
            self._since = now
        since = max(self._since, self.inflight.last_change)
        return now - since >= self._quiet
