"""Structured logging shared by every tool.

Each log line is JSON carrying the run context (``run_id``, ``tool``,
``identity``, ``flow_id``) so runs are reproducible and greppable. Values that
look secret-ish are redacted defensively.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

_REDACT = ("password", "secret", "token", "cookie", "authorization", "credential")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        for key in ("run_id", "tool", "identity", "flow_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(_redact(extra))
        return json.dumps(payload, default=str)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("***" if any(t in k.lower() for t in _REDACT) else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class _ContextAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]):
        extra = dict(self.extra or {})
        caller_extra = kwargs.pop("extra", None)
        if caller_extra:
            extra["extra_fields"] = caller_extra
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(tool: str, run_id: int | None = None, identity: str | None = None,
               level: int = logging.INFO) -> logging.LoggerAdapter:
    """Return a logger that stamps every line with the run context."""
    logger = logging.getLogger(f"fuzzlab.{tool}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    context = {"tool": tool}
    if run_id is not None:
        context["run_id"] = run_id
    if identity is not None:
        context["identity"] = identity
    return _ContextAdapter(logger, context)
