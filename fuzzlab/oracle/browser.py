"""Browser-execution seam for the oracle (M6): confirm stored/DOM XSS.

Reflected XSS is confirmed by inspecting the response (M5). Stored and DOM XSS only
prove themselves when the injected script *executes in a browser* — so the oracle
needs a real browser, injected behind this seam exactly like the HTTP `Sender`, so
the strategies stay unit-testable offline with a `FakeBrowserExecutor`. The live
Playwright-backed executor lives in `fuzzlab/tools/browserexec.py` (on-host).

The contract: the strategy builds a payload that calls a **sentinel** function with a
unique token; the executor defines that sentinel before navigation, drives the page
(optionally storing first, for stored XSS), and reports whether the token actually
fired. Confirmation is execution, never mere reflection (fail-closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# The sentinel the payload calls and the executor defines. A confirmed execution is
# ``window.SENTINEL('<token>')`` actually running (not the string being reflected).
SENTINEL = "__fzlbHit"


@dataclass
class StoreStep:
    """A write that plants the payload before the observe page is loaded (stored XSS)."""
    url: str
    param: str
    value: str
    method: str = "POST"
    location: str = "body"


@dataclass
class ExecRequest:
    """Load ``url`` in a browser (after ``store``, if given) with ``value`` placed in
    ``param`` at ``location`` (query or fragment), and watch for the sentinel."""
    url: str
    param: str | None = None
    value: str | None = None
    location: str = "query"                 # query | fragment
    store: StoreStep | None = None


@dataclass
class ExecObservation:
    executed: bool                          # did the tokened sentinel actually fire?
    detail: str = ""                        # how (onerror/script/…), for evidence


@runtime_checkable
class BrowserExecutor(Protocol):
    def run(self, request: ExecRequest, token: str) -> ExecObservation:
        ...


class FakeBrowserExecutor:
    """Offline fake: 'executes' iff the payload reached an executable sink.

    A ``vulnerable`` predicate over ``(request)`` models whether the page would run
    the injected script; when it does, the token is considered fired. Defaults to a
    simple heuristic (an ``onerror``/``onload``/``<script>`` payload not HTML-escaped),
    so a test can pass a vulnerable vs escaped page without a real browser.
    """

    def __init__(self, vulnerable=None, escape: bool = False):
        self._vulnerable = vulnerable
        self._escape = escape                # simulate a page that HTML-escapes input

    def run(self, request: ExecRequest, token: str) -> ExecObservation:
        value = request.value or ""
        if self._vulnerable is not None:
            fired = bool(self._vulnerable(request))
        else:
            executable = ("onerror=" in value or "onload=" in value
                          or "<script" in value.lower())
            fired = executable and not self._escape and token in value
        return ExecObservation(executed=fired, detail="fake" if fired else "")
