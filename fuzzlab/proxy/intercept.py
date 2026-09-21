"""Interactive interception as an awaited future (FR-PROXY-6).

The classic Burp intercept model, expressed with asyncio: when interception is on, the
data path *awaits* a decision for each message — the flow is held pending until a user
(the control panel, a test, a script) forwards it (optionally edited) or drops it. When
interception is off, ``handle`` returns the message unchanged immediately, so the proxy
stays a transparent observer (D5).

This is sans-I/O: it holds :class:`RawMessage` values and resolves futures. Wiring it to
sockets is the on-host server (T6.6).
"""

from __future__ import annotations

import asyncio
import itertools
from dataclasses import dataclass, field

from fuzzlab.proxy.message import RawMessage


@dataclass
class PendingFlow:
    id: int
    message: RawMessage
    direction: str                       # "request" | "response"
    host: str = ""
    future: asyncio.Future = field(default=None, repr=False)


class Interceptor:
    """Holds messages pending a forward/drop decision when enabled."""

    def __init__(self, enabled: bool = True, intercept_responses: bool = False):
        self.enabled = enabled
        # Whether to also hold responses (the engine consults this before its response
        # hook); default off, so enabling interception pauses requests only.
        self.intercept_responses = intercept_responses
        self._ids = itertools.count(1)
        self._pending: dict[int, PendingFlow] = {}

    def set_enabled(self, on: bool) -> None:
        """Turn interception on/off. Turning it off releases all held flows unedited."""
        self.enabled = on
        if not on:
            for flow in list(self._pending.values()):
                self.forward(flow.id)

    def set_intercept_responses(self, on: bool) -> None:
        """Toggle holding responses too. Turning it off releases any held responses."""
        self.intercept_responses = on
        if not on:
            for flow in list(self._pending.values()):
                if flow.direction == "response":
                    self.forward(flow.id)

    async def handle(self, message: RawMessage, direction: str = "request",
                     host: str = "") -> RawMessage | None:
        """Await a decision for ``message``; return the (possibly edited) message, or
        ``None`` if it was dropped. Returns immediately when interception is off."""
        if not self.enabled:
            return message
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        flow = PendingFlow(id=next(self._ids), message=message,
                           direction=direction, host=host, future=fut)
        self._pending[flow.id] = flow
        try:
            return await fut
        finally:
            self._pending.pop(flow.id, None)

    # --- control surface (UI/tests/scripts) ---------------------------------
    def pending(self) -> list[PendingFlow]:
        return list(self._pending.values())

    def get(self, flow_id: int) -> PendingFlow | None:
        return self._pending.get(flow_id)

    def forward(self, flow_id: int, message: RawMessage | None = None) -> None:
        """Release a held flow, optionally replacing it with an edited message."""
        flow = self._pending.get(flow_id)
        if flow is None or flow.future.done():
            return
        flow.future.set_result(message if message is not None else flow.message)

    def drop(self, flow_id: int) -> None:
        """Drop a held flow (the data path gets ``None`` and sends nothing)."""
        flow = self._pending.get(flow_id)
        if flow is None or flow.future.done():
            return
        flow.future.set_result(None)
