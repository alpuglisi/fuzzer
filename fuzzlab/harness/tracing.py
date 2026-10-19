"""The fuzzing pipeline's exchange instrumentation (FR-FUZZ-60).

`TracingSender` sits directly around the run's real probe sender -- every request the
pipeline and the oracle make passes it, whichever sender is in use -- and records each
send as one ``exchange`` event (`core.trace`): its test, strategy and role from the
execution context (`trace.test_scope`, `strategy_scope`, `role`), the point's method,
URL (redacted), parameter name and location, a digest and short preview of the value the
tool sent (none for a sensitive parameter), and what came back. What came back is never
upgraded: a response has its status and time; a timeout is ``timeout``; no response is
``unobserved``; a refusal before sending is ``not_sent``; any other failure is ``error``
with its class. A PRG follow-up the sender made is its own ``exchange`` (role
``follow-up``) whose ``parent`` is the probe's key. A re-send the sender made after a
reset is counted on the exchange (``resent``), not recorded as its own attempt: the
senders do not expose each try (stated limitation).
"""

from __future__ import annotations

import time

from fuzzlab.core import trace
from fuzzlab.core.urls import canonical_origin


class TracingSender:
    def __init__(self, inner, identity: str | None = None):
        self._inner = inner
        self._identity = identity or "anonymous"

    def __getattr__(self, name):                 # header breaker, notes, ... (read-only)
        return getattr(self._inner, name)

    @property
    def prg_capable(self) -> bool:
        from fuzzlab.oracle.probe import accepts_prg
        return accepts_prg(self._inner)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        def forward():
            # the same call shapes `_CountingSender` uses, so test fakes keep working
            if prg:
                return self._inner.send(url, param, value, timing=timing, method=method,
                                        location=location, content_type=content_type,
                                        entries=entries, prg=True)
            if entries is not None:
                return self._inner.send(url, param, value, timing=timing, method=method,
                                        location=location, entries=entries)
            if method == "GET" and location == "query":
                return self._inner.send(url, param, value, timing=timing)
            if content_type:
                return self._inner.send(url, param, value, timing=timing, method=method,
                                        location=location, content_type=content_type)
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location)

        if trace.active() is None:
            return forward()
        from fuzzlab.oracle.probe import Probe, ProbeUnobserved, UnplaceableLocation
        test, strategy, role = trace.current()
        digest, length = trace.value_digest(value)
        body = {"test": test, "strategy": strategy, "role": role or "probe",
                "method": (method or "GET").upper(), "url": trace.safe_ref(url),
                "origin": canonical_origin(url), "param": param, "location": location,
                "value_sha": digest, "value_len": length,
                "value_preview": trace.value_preview(param, value), "timing": timing,
                "identity": self._identity, "prg_asked": bool(prg)}
        started = time.time()
        clock = time.perf_counter()
        probe = None
        try:
            probe = forward()
        except UnplaceableLocation as exc:
            body.update(outcome="not_sent", error=type(exc).__name__)
            raise
        except ProbeUnobserved as exc:
            body.update(outcome="unobserved", error=type(exc.__cause__ or exc).__name__,
                        resent=exc.resent)
            raise
        except Exception as exc:
            from fuzzlab.tools.probesender import _is_timeout
            body.update(outcome="timeout" if _is_timeout(exc) else "error",
                        error=type(exc).__name__)
            raise
        finally:
            body["elapsed_ms"] = round((time.perf_counter() - clock) * 1000, 1)
            if probe is not None and isinstance(probe, Probe):
                if probe.status == 0:            # the unauthenticated sender's timeout
                    body.update(outcome="timeout", resent=probe.resent)
                else:
                    body.update(outcome="response", status=probe.status,
                                resent=probe.resent,
                                location=trace.safe_ref(
                                    (probe.headers or {}).get("Location")
                                    or (probe.headers or {}).get("location") or "")
                                or None,
                                session=probe.session, prg=probe.prg)
            key = trace.emit("exchange", body, scope=f"test:{test}" if test else "run",
                             t=started)
            if key is not None:
                collected = trace._EXCHANGES.get()
                if collected is not None:
                    collected.append(key)
                if probe is not None and isinstance(probe, Probe) and \
                        probe.followed is not None:
                    self._follow_up(key, probe.followed, body, started)
        return probe

    def _follow_up(self, parent: str, followed, body: dict, started: float) -> None:
        url = followed.url or ""
        child = {"test": body["test"], "strategy": body["strategy"], "role": "follow-up",
                 "parent": parent, "method": "GET", "url": trace.safe_ref(url),
                 "origin": canonical_origin(url) or body["origin"], "param": None,
                 "location": None, "identity": body["identity"],
                 "outcome": "timeout" if followed.status == 0 else "response",
                 "status": followed.status or None,
                 "elapsed_ms": round((followed.elapsed or 0) * 1000, 1)}
        key = trace.emit("exchange", child,
                         scope=f"test:{body['test']}" if body["test"] else "run",
                         t=started)
        collected = trace._EXCHANGES.get()
        if key and collected is not None:
            collected.append(key)
