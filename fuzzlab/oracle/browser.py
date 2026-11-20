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

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from fuzzlab.oracle.probe import UnplaceableLocation

# The sentinel the payload calls and the executor defines. A confirmed execution is
# ``window.SENTINEL('<token>')`` actually running (not the string being reflected).
SENTINEL = "__fzlbHit"


class NotObserved(UnplaceableLocation):
    """The executor started, but this probe's page could not be observed: its plant or
    observe navigation failed or timed out, or it never finished loading, and no hit
    was recorded (BUG-0137). Per payload: the strategy tries its next payload, and with
    no hit at all it is inconclusive (FR-FUZZ-45), never a negative. A browser that
    cannot start is the plain `UnplaceableLocation` (BUG-0126): it stops at once."""


@dataclass
class StoreStep:
    """A write that plants the payload before the observe page is loaded (stored XSS)."""
    url: str
    param: str
    value: str
    method: str = "POST"
    location: str = "body"                  # body (a form) | query (a GET) | json
    #: a JSON body's leaves (`core.jsonbody` entries); the payload replaces ``param``'s
    entries: tuple | None = None


@dataclass
class ExecRequest:
    """Load ``url`` in a browser (after ``store``, if given) with ``value`` placed in
    ``param`` at ``location`` (query or fragment), and watch for the sentinel."""
    url: str
    param: str | None = None
    value: str | None = None
    location: str = "query"                 # query | fragment
    store: StoreStep | None = None
    #: a query point's bound sibling entries (a crawled link set's, ``[(name, value)]``):
    #: the observe load's query is these, bound by the binder's rule
    #: (`core.urls.bind_query`, FR-FUZZ-64), as the HTTP senders send them. None: the
    #: URL's own query, the standalone rule (`place_query_param`)
    entries: tuple | None = None


@dataclass
class ExecObservation:
    executed: bool                          # did the tokened sentinel actually fire?
    detail: str = ""                        # how (onerror/script/…), for evidence
    #: FR-FUZZ-721: every sentinel token that fired on the page -- its own and any other
    #: (a stored sibling payload's echo). The strategy credits a hit to the payload whose
    #: token fired, never to the page that saw it. Empty: the executor reports its own
    #: token only (``executed``).
    hits: frozenset = field(default_factory=frozenset)


@runtime_checkable
class BrowserExecutor(Protocol):
    def run(self, request: ExecRequest, token: str) -> ExecObservation:
        ...


def observe_many(executor, items) -> list:
    """FR-FUZZ-720: ``[(request, token), ...]`` observed by ``executor``: its own
    `run_many` (concurrent, bounded by its ``workers``) when it has one, else ``run``
    one after another. One result per item, in order: the observation, the exception
    ``run`` raised for that item (handed back, never raised here), or None for an item
    `run_many` left unobserved (an earlier item's refusal)."""
    many = getattr(executor, "run_many", None)
    if many is not None:
        return list(many(items))
    out = []
    for request, token in items:
        try:
            out.append(executor.run(request, token))
        except Exception as exc:  # noqa: BLE001 - the item's own result
            out.append(exc)
    return out


def workers_of(executor) -> int:
    """How many visits ``executor`` observes at a time (FR-FUZZ-722): its ``workers``
    when it has `run_many`, else 1."""
    if getattr(executor, "run_many", None) is None:
        return 1
    workers = getattr(executor, "workers", 1)
    return workers if isinstance(workers, int) and workers >= 1 else 1


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
