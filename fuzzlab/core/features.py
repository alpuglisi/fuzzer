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


# --- candidate features (FR-ML-5, CC-CORE-0031) ------------------------------------------
#
# The candidate vector the classifier, ranker, budget prioritizer and anomaly tripwire
# read: derived only from what discovery/audit record about an injection point (its
# location, method, sink, category, parameter name shape and how many rules fired) —
# never the payload, never the oracle's verdict. Moved here verbatim from
# `fuzzlab.ml.dataset._features` (pinned by `tests/data/candidate_features/v1_golden.json`,
# captured before the move). Its version counter is separate from `FEATURE_VERSION`
# above (the response-behaviour extractor): the two vectors version independently.
# Recomputed on read: `candidate.features_json` / `feature_version` stay unwritten.

import re as _re

CANDIDATE_FEATURE_NAMES = [
    "loc_body", "method_post", "has_sink", "cat_sqli", "cat_xss",
    "param_len", "name_id", "name_redirect", "name_file", "name_cmd", "rules_fired",
]
CANDIDATE_FEATURE_VERSION = 1
#: Locations the ``loc_body`` feature counts as a request body (``json``: one leaf of a
#: JSON body, `core.jsonbody.LOCATION`).
_BODY_LOCATIONS = frozenset({"body", "json"})

_RE_ID = _re.compile(r"(^id$|_id$|^id_|id$)", _re.I)
_RE_REDIR = _re.compile(r"url|next|redirect|return|dest|goto|continue|target", _re.I)
_RE_FILE = _re.compile(r"file|path|page|include|template|doc|folder|dir|load", _re.I)
_RE_CMD = _re.compile(r"cmd|exec|command|ping|host|dns|domain|ip", _re.I)


def extract_candidate_v1(ev: dict, sink_context, rules_fired: int) -> list[float]:
    """The v1 candidate vector, in `CANDIDATE_FEATURE_NAMES` order. ``loc_body`` is 1 for
    a ``json`` point too (a leaf of a request body; forms phase 3, CC-ML-0030): no
    stored row had that location before, so no v1 vector changes and the version
    stays."""
    name = ev.get("param", "") or ""
    loc = ev.get("location", "query")
    method = (ev.get("method", "GET") or "GET").upper()
    cat = ev.get("category", "")
    return [
        1.0 if loc in _BODY_LOCATIONS else 0.0,
        1.0 if method == "POST" else 0.0,
        1.0 if sink_context else 0.0,
        1.0 if cat == "sql-injection" else 0.0,
        1.0 if cat == "xss" else 0.0,
        float(len(name)),
        1.0 if _RE_ID.search(name) else 0.0,
        1.0 if _RE_REDIR.search(name) else 0.0,
        1.0 if _RE_FILE.search(name) else 0.0,
        1.0 if _RE_CMD.search(name) else 0.0,
        float(rules_fired),
    ]
