"""Server-Sent Events helpers for the control panel.

One-way server→client streaming (run output, proxy events, live metrics) uses SSE
rather than WebSockets — it is a plain ``text/event-stream`` HTTP response, so it
needs no extra dependency and works with the loopback-only server. ``format_event``
is pure and unit-tested; ``sse_response`` is a thin ``StreamingResponse`` wrapper.

The first live consumer is the Phase 0.3 subprocess runner (streamed stdout).
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator


def format_event(data: Any, *, event: str | None = None, id: str | None = None) -> str:
    """Serialize one SSE message to the wire format.

    Non-string ``data`` is JSON-encoded. Multi-line data is split into one
    ``data:`` line each (per the SSE spec), so newlines survive intact.
    """
    lines: list[str] = []
    if id is not None:
        lines.append(f"id: {id}")
    if event is not None:
        lines.append(f"event: {event}")
    if not isinstance(data, str):
        data = json.dumps(data, separators=(",", ":"))
    for line in data.split("\n"):
        lines.append(f"data: {line}")
    return "\n".join(lines) + "\n\n"


def sse_response(events: AsyncIterator[str]):
    """Wrap an async iterator of already-formatted events in a StreamingResponse.

    Callers format each item with :func:`format_event`. Headers disable proxy/
    browser buffering so events flush immediately.
    """
    from fastapi.responses import StreamingResponse

    return StreamingResponse(
        events,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
