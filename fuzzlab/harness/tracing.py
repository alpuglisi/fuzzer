"""The fuzzing pipeline's exchange instrumentation (FR-FUZZ-60, FR-FUZZ-61).

`TracingSender` sits directly around the run's real probe sender -- every request the
pipeline and the oracle make passes it, whichever sender is in use -- and records each
send as one ``exchange`` event (`core.trace`): its test, strategy and role from the
execution context (`trace.test_scope`, `strategy_scope`, `role`), the point's method,
URL (redacted), parameter name and location, a digest and short preview of the value the
tool sent (none for a sensitive parameter), and what came back. What came back is never
upgraded: a response has its status and time; a timeout is ``timeout``; no response is
``unobserved``; a refusal before sending is ``not_sent``; any other failure is ``error``
with its class. A PRG follow-up the sender sent is its own ``exchange`` (role
``follow-up``) whose ``parent`` is the probe's key -- observed or not (`Probe.prg_sent`,
BUG-0510): a follow-up answered by another redirect, timed out or unobserved is
recorded with that outcome.

Each try is evidence (FR-FUZZ-61). The senders record every try where it happens
(`Probe.attempts`, `ProbeUnobserved.attempts`, `oracle.probe.attempts_of`). When an
exchange took more than one try, each earlier try is its own ``exchange`` event (role
``retry``, ``parent`` = the exchange it retried, ``attempt`` = its number, its own
outcome, status and time), written before that exchange so the recorder's order is the
order of the tries. The exchange keeps its final outcome and carries ``attempts`` (the
count) and ``resent`` (its own re-sends, ``attempts - 1``: `Probe.resent` is a run
counter that also counts the follow-up's, BUG-0510). A sender that records no tries (a
test double) gives no ``attempts`` field and no ``retry`` event, and ``resent`` is
`Probe.resent` as before.
"""

from __future__ import annotations

import time
import uuid

from fuzzlab.core import trace
from fuzzlab.core.urls import canonical_origin

#: What a ``retry`` event repeats of the exchange it retried: the same request.
_RETRY_KEEPS = ("test", "strategy", "method", "url", "origin", "param", "location",
                "value_sha", "value_len", "value_preview", "timing", "identity")


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

    @property
    def fetch_capable(self) -> bool:
        from fuzzlab.oracle.probe import accepts_fetch
        return accepts_fetch(self._inner)

    def fetch(self, url, *, route_url):
        """The binder's page fetch (FR-FUZZ-67), recorded as its own exchange (role
        ``bind``): a request the run made. It carries no value; the page's text, which
        holds the fresh value, is never recorded (D12)."""
        if trace.active() is None:
            return self._inner.fetch(url, route_url=route_url)
        from fuzzlab.oracle.probe import Probe, ProbeUnobserved, attempts_of
        test, strategy, _role = trace.current()
        body = {"test": test, "strategy": strategy, "role": "bind", "method": "GET",
                "url": trace.safe_ref(url), "origin": canonical_origin(url),
                "param": None, "location": None, "value_sha": None, "value_len": 0,
                "value_preview": None, "timing": False, "identity": self._identity,
                "prg_asked": False}
        started = time.time()
        clock = time.perf_counter()
        probe, tries = None, []
        try:
            probe = self._inner.fetch(url, route_url=route_url)
        except ProbeUnobserved as exc:
            tries = attempts_of(exc)
            body.update(outcome="unobserved", error=type(exc.__cause__ or exc).__name__)
            raise
        except Exception as exc:
            tries = attempts_of(exc)
            body.update(outcome="error", error=type(exc).__name__)
            raise
        finally:
            body["elapsed_ms"] = round((time.perf_counter() - clock) * 1000, 1)
            if isinstance(probe, Probe):
                tries = attempts_of(probe)
                body.update(outcome="timeout" if probe.status == 0 else "response",
                            status=probe.status or None, session=probe.session)
            self._exchange(body, tries, started)
        return probe

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
        from fuzzlab.oracle.probe import (Probe, ProbeUnobserved, UnplaceableLocation,
                                          attempts_of)
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
        tries: list[dict] = []
        try:
            probe = forward()
        except UnplaceableLocation as exc:
            body.update(outcome="not_sent", error=type(exc).__name__)
            raise
        except ProbeUnobserved as exc:
            tries = attempts_of(exc)
            body.update(outcome="unobserved", error=type(exc.__cause__ or exc).__name__,
                        resent=exc.resent)
            raise
        except Exception as exc:
            from fuzzlab.tools.probesender import _is_timeout
            tries = attempts_of(exc)
            body.update(outcome="timeout" if _is_timeout(exc) else "error",
                        error=type(exc).__name__)
            raise
        finally:
            body["elapsed_ms"] = round((time.perf_counter() - clock) * 1000, 1)
            if probe is not None and isinstance(probe, Probe):
                tries = attempts_of(probe)
                if probe.status == 0:            # the unauthenticated sender's timeout
                    body.update(outcome="timeout", resent=probe.resent)
                else:
                    body.update(outcome="response", status=probe.status,
                                resent=probe.resent,
                                redirect=trace.safe_ref(
                                    (probe.headers or {}).get("Location")
                                    or (probe.headers or {}).get("location") or "")
                                or None,
                                session=probe.session, prg=probe.prg)
            key = self._exchange(body, tries, started)
            if key is not None:
                sent = _follow_up_sent(probe)
                if sent is not None:
                    self._follow_up(key, sent, body, started)
        return probe

    @staticmethod
    def _exchange(body: dict, tries: list[dict], started: float) -> str | None:
        """Record one exchange and, before it, each of its earlier tries (``retry``)."""
        scope = f"test:{body['test']}" if body["test"] else "run"
        if tries:
            # this exchange's own re-sends: `Probe.resent` also counts its follow-up's
            # (a run counter, BUG-0147), so it is read only from a sender without tries
            body.update(attempts=len(tries), resent=len(tries) - 1)
        key = None
        if len(tries) > 1:
            key = f"exchange:{uuid.uuid4().hex[:20]}"   # its retries name it first
            for tried in tries[:-1]:
                retry = {k: body.get(k) for k in _RETRY_KEEPS}
                retry.update(role="retry", parent=key, attempt=tried.get("n"),
                             outcome=tried.get("outcome"), status=tried.get("status"),
                             elapsed_ms=tried.get("elapsed_ms"), error=tried.get("error"))
                _collect(trace.emit("exchange", retry, scope=scope, t=started))
        key = trace.emit("exchange", body, key=key, scope=scope, t=started)
        _collect(key)
        return key

    def _follow_up(self, parent: str, sent: dict, body: dict, started: float) -> None:
        url = sent.get("url") or ""
        child = {"test": body["test"], "strategy": body["strategy"], "role": "follow-up",
                 "parent": parent, "method": "GET", "url": trace.safe_ref(url),
                 "origin": canonical_origin(url) or body["origin"], "param": None,
                 "location": None, "identity": body["identity"],
                 "outcome": sent.get("outcome"), "status": sent.get("status"),
                 "elapsed_ms": sent.get("elapsed_ms")}
        if sent.get("error"):
            child["error"] = sent["error"]
        tries = [a for a in sent.get("attempts") or [] if isinstance(a, dict)]
        self._exchange(child, tries, started)


def _collect(key: str | None) -> None:
    """Add an exchange key to the current strategy scope's (`trace.collected`)."""
    collected = trace._EXCHANGES.get()
    if key and collected is not None:
        collected.append(key)


def _follow_up_sent(probe) -> dict | None:
    """The PRG follow-up a probe's sender sent: its own record (`Probe.prg_sent`), or,
    from a sender that keeps none, the observation (``followed``) as before."""
    from fuzzlab.oracle.probe import Probe, attempts_of
    if not isinstance(probe, Probe):
        return None
    if isinstance(probe.prg_sent, dict):
        return probe.prg_sent
    followed = probe.followed
    if followed is None:
        return None
    return {"url": followed.url or "",
            "outcome": "timeout" if followed.status == 0 else "response",
            "status": followed.status or None,
            "elapsed_ms": round((followed.elapsed or 0) * 1000, 1), "error": None,
            "attempts": attempts_of(followed)}
