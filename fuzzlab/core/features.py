"""One versioned feature extractor.

Features are written with a ``feature_version`` so the whole dataset can be
recomputed when features change (feature-store discipline, D5/D10). Extractors
are pure and deterministic: the same (request, response, baseline) always yields
the same vector, which the golden-file tests pin.

Rule for ML honesty (D10): features must **not** encode the payload string —
that would leak the label. Extractors here derive only from response behavior and
request shape, never from the payload content.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

FEATURE_VERSION = 1


@dataclass
class Observation:
    """Minimal, transport-agnostic view an extractor needs."""
    status: int
    elapsed_ms: float
    body: bytes
    headers: dict[str, str]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_v1(request: Observation, response: Observation,
               baseline: Observation | None) -> dict[str, Any]:
    """Behavioral features (v1). No payload string is ever read here."""
    body = response.body or b""
    text = body.decode("utf-8", errors="replace")
    lower = text.lower()

    feats: dict[str, Any] = {
        "status": response.status,
        "elapsed_ms": round(response.elapsed_ms, 3),
        "content_length": len(body),
        "body_entropy": round(_entropy(body), 4),
        "num_tags": lower.count("<"),
        "has_sql_error": int(any(
            marker in lower for marker in (
                "sql syntax", "sqlstate", "mysql_fetch", "ora-", "psql", "sqlite3",
                "you have an error in your sql", "unclosed quotation",
            )
        )),
        "status_class": response.status // 100,
    }

    if baseline is not None:
        base_body = baseline.body or b""
        feats["len_delta"] = len(body) - len(base_body)
        feats["elapsed_delta_ms"] = round(response.elapsed_ms - baseline.elapsed_ms, 3)
        feats["status_changed"] = int(response.status != baseline.status)
    else:
        feats["len_delta"] = 0
        feats["elapsed_delta_ms"] = 0.0
        feats["status_changed"] = 0

    return feats


_EXTRACTORS = {1: extract_v1}


def extract(request: Observation, response: Observation,
            baseline: Observation | None = None,
            version: int = FEATURE_VERSION) -> dict[str, Any]:
    """Dispatch to the requested feature version (default: current)."""
    try:
        extractor = _EXTRACTORS[version]
    except KeyError:  # pragma: no cover - guard
        raise ValueError(f"unknown feature_version {version}")
    return extractor(request, response, baseline)
