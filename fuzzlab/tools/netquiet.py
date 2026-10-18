"""Network quiet for a browser page: the requests a settle waits for (SP-40).

Every browser path that waits for "the page's requests to finish" after a load, a click
or a submission counts the page's requests in flight and waits for that count to be
zero. A request that is *meant* to stay open never lets it reach zero: a long-poll
(socket.io's ``polling`` transport holds a GET open about 25 s and reissues it at
once), a server-sent event stream, a streamed download. Every settle then ran to its
budget: on Juice Shop the crawler spent 64% of its self time in ``_settle`` (503
calls, often to the 5 s cap; CC-CRAWL-0037's profile).

`Inflight` counts the requests a settle should wait for:

* never an ``eventsource`` or ``websocket`` request (open by design);
* never a request open longer than `LONG_LIVED_MS` -- an app's own XHR answered by a
  loopback lab finishes well within it, a long-poll does not. Its end is not activity
  either, so a poll that is answered and reissued does not restart a quiet period.

Not waiting for a request does not let anything through: a request in flight has
already passed the guard and any write window when it was sent; what is sent later is
checked as before.
"""

from __future__ import annotations

import time
from typing import Callable

#: A request still open after this long is long-lived (a long-poll, a stream): no
#: settle waits for it.
LONG_LIVED_MS = 2000
#: Resource types that are open by design.
STREAMING_TYPES = frozenset({"eventsource", "websocket"})


class Inflight:
    """Requests in flight on the pages it is attached to, minus long-lived ones.

    ``n`` is the number a settle waits to see at zero; ``last_change`` (a ``clock``
    reading) the last start or end of a request it counts."""

    def __init__(self, page=None, *, clock: Callable[[], float] = time.monotonic,
                 long_lived_ms: int = LONG_LIVED_MS):
        self._clock = clock
        self._long = long_lived_ms / 1000
        self._open: dict = {}                  # request -> when it started
        self.last_change = clock()
        if page is not None:
            self.attach(page)

    def attach(self, page) -> None:
        page.on("request", self.started)
        page.on("requestfinished", self.ended)
        page.on("requestfailed", self.ended)

    def started(self, request) -> bool:
        """Count ``request``; whether it is one a settle waits for."""
        if getattr(request, "resource_type", None) in STREAMING_TYPES:
            return False
        now = self._clock()
        self._open[request] = now
        self.last_change = now
        return True

    def ended(self, request) -> bool:
        """Forget ``request``; whether its end is activity (it was counted, not yet
        long-lived)."""
        began = self._open.pop(request, None)
        if began is None:
            return False
        now = self._clock()
        if now - began >= self._long:
            return False                       # a long-poll answered: not activity
        self.last_change = now
        return True

    @property
    def n(self) -> int:
        now = self._clock()
        return sum(1 for began in self._open.values() if now - began < self._long)

    @property
    def long_lived(self) -> int:
        """Requests open past `LONG_LIVED_MS` (reported, never waited for)."""
        return len(self._open) - self.n
