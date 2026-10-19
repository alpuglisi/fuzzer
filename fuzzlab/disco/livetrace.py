"""A disco capture's trace, written while it runs (FR-CRAWL-30, `core.trace`).

``fuzzlab disco capture --store PATH`` (or ``--record``) starts one store run (``run.tool``
``disco``) and a `LiveTrace` over the run directory. The capture itself is not touched:
the trace reads the files the capture writes (`capture.jsonl` through SP-35's
`capture.CaptureTail`, ``actions.jsonl`` through `observe.DiscoActionLines`) and builds
every event with `tools.observe`'s builders (FR-AUD-29), so its keys and bodies are the
import's.

**One writer (SP-48).** One thread, ``disco-trace``, in the capture command's process,
with its own `Store` connection and the run's one `trace.TraceRecorder`. mitmdump (another
process) and the explorer's threads never write the trace.

**Live pass**, every `POLL_S`: the complete records and action lines added since the last
pass (a line whose newline has not arrived waits; measured, a reader can see half a line),
then one flush. An action line without an ``action_id`` (an old log) waits for the final
pass, which knows every record. Each item is guarded: an item that cannot be built is
counted ``dropped`` and logged, and the pass goes on.

**Final pass**, when the capture has ended (`stop`, after the capture proxy stopped and
``explore.json`` was written): the directory imported into the run by `observe_disco`
itself, on the same recorder, then ``run.end`` and the counters. Whatever the live pass
did not write -- a batch the store refused, the last unterminated line, old-log actions,
the hosts the capture proxy and the browser guard refused (final counts) -- is written
then, and the run's events equal the import's. A batch once dropped stays counted
(``trace_dropped``), so the run still reads partial.

**A failed trace never fails the capture.** A failure escaping a pass stops the trace: it
is printed to stderr at once, the run ends ``aborted: trace <class>`` and its row is
marked, and `stop` returns the reason (never raises). `stop` waits `join_bound` seconds:
each flush under a write lock another process holds can take ~20 s (10 s on the insert,
10 s on the counters; measured), so the bound grows with the flushes the final pass
needs; past it the caller reports a timeout.
"""

from __future__ import annotations

import math
import sys
import threading
from pathlib import Path

from fuzzlab.core import trace
from fuzzlab.disco.capture import CaptureTail, read_capture
from fuzzlab.tools import observe

#: Seconds between live passes. Measured: a record is in the store p95 0.25 s after its
#: response; the Diagrams page polls every 3 s.
POLL_S = 0.25
#: The floor of `join_bound`: a live pass in flight, the final flush and the counters
#: under a held write lock (measured 20.1 + 20.1 + 10.0 s), with margin.
JOIN_TIMEOUT_S = 60.0
#: One flush under a held write lock: the insert's and the counters' busy timeouts.
FLUSH_STALL_S = 20.0


class LiveTraceFailed(RuntimeError):
    """The live trace stopped on an error; the capture went on."""


def join_bound(events: int) -> float:
    """How long `LiveTrace.stop` waits: `JOIN_TIMEOUT_S`, or more when the final pass
    needs more flushes than one (``ceil(events / MAX_BUFFER)`` forced flushes, plus the
    pass in flight and the counters)."""
    flushes = math.ceil((events + 1) / trace.MAX_BUFFER)
    return max(JOIN_TIMEOUT_S, FLUSH_STALL_S * (flushes + 1) + FLUSH_STALL_S)


class LiveTrace:
    """``live = LiveTrace(run_dir, store_path, run_id); live.start()`` ... capture ...
    ``problem = live.stop("complete")``. `open`, `poll` and `finish` are the thread's
    steps, callable in order from one thread (tests)."""

    def __init__(self, run_dir, store_path, run_id: int, *, poll_s: float | None = None):
        self.run_dir = Path(run_dir)
        self.store_path = Path(store_path)
        self.run_id = run_id
        self.poll_s = POLL_S if poll_s is None else poll_s
        self.tag = observe.disco_tag(self.run_dir)
        self.failure: str | None = None
        self.stats: dict = {}
        self.store = None
        self.recorder: trace.TraceRecorder | None = None
        self._capture = CaptureTail(self.run_dir / "capture.jsonl")
        self._actions = observe.DiscoActionLines(self.run_dir / "actions.jsonl")
        self._stop = threading.Event()
        self._status = "aborted"
        self._thread: threading.Thread | None = None

    # --- the thread ----------------------------------------------------------------
    def start(self) -> LiveTrace:
        self._thread = threading.Thread(target=self._run, name="disco-trace", daemon=True)
        self._thread.start()
        return self

    def stop(self, status: str) -> str | None:
        """End the trace with ``status`` (``complete``, ``aborted: <class>``): the final
        pass, ``run.end``, the counters. Never raises; returns None, the failure that
        stopped the trace, or a timeout."""
        self._status = status
        self._stop.set()
        if self._thread is None:
            return self.failure
        bound = join_bound(self._capture.count + self._actions.lineno)
        self._thread.join(bound)
        if self._thread.is_alive():
            return (f"timeout: the live trace did not finish within {bound:.0f} s; run "
                    f"{self.run_id} has no end recorded")
        return self.failure

    def _run(self) -> None:
        try:
            self.open()
            while not self._stop.wait(self.poll_s):
                self.poll()
            self.finish(self._status)
        except Exception as exc:  # noqa: BLE001 - the trace stops; the capture goes on
            self._fail(exc)
        finally:
            if self.store is not None:
                self.store.close()

    # --- the steps -------------------------------------------------------------------
    def open(self) -> None:
        from fuzzlab.core.store import Store
        self.store = Store(self.store_path)
        self.recorder = trace.TraceRecorder(self.store, self.run_id)

    def poll(self) -> None:
        """One live pass: what was completed since the last, then one flush."""
        with trace.recording(self.recorder):
            try:
                records = self._capture.read()
            except FileNotFoundError:
                records = []
            for i, rec in records:
                self._item(observe.emit_capture_record, self.tag, i, rec)
            for lineno, doc in self._actions.read():
                if doc is not None and doc.get("action_id"):
                    self._item(observe.emit_disco_action, self.tag, lineno, doc, {})
            self.recorder.flush()

    def finish(self, status: str) -> None:
        """The final pass: the directory imported into the run, then its end."""
        with trace.recording(self.recorder):
            observe.observe_disco(self.run_dir,
                                  read_capture(self.run_dir / "capture.jsonl").records)
            trace.emit("run.end", {"status": status}, key="run.end", scope="run")
        self.stats = self.recorder.close()

    def _item(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as exc:  # noqa: BLE001 - counted, logged, the pass goes on
            self.recorder.stats["dropped"] += 1
            from fuzzlab.core.obs import get_logger
            get_logger("trace").warning("live trace item not built",
                                        extra={"error": type(exc).__name__})

    def _fail(self, exc: BaseException) -> None:
        self.failure = f"{type(exc).__name__}: {str(exc)[:200]}"
        print(f"fuzzlab disco: the live trace stopped ({self.failure}); the capture goes "
              f"on", file=sys.stderr)
        why = LiveTraceFailed(f"trace {type(exc).__name__}")
        try:
            if self.recorder is not None:
                self.recorder.emit("run.end", {"status": f"aborted: trace "
                                                         f"{type(exc).__name__}"},
                                   key="run.end", scope="run")
                self.stats = self.recorder.close()
        except Exception as again:  # noqa: BLE001 - best effort; the reason is reported
            from fuzzlab.core.obs import get_logger
            get_logger("trace").warning("live trace end not written",
                                        extra={"error": type(again).__name__})
        if self.store is not None:
            self.store.mark_aborted(self.run_id, why)
