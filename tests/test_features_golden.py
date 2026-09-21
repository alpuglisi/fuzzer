"""Golden-file tests for the versioned feature extractor (T0.5).

Fixed (request, response, baseline) triples must always produce the recorded
vector. If a feature legitimately changes, bump FEATURE_VERSION and regenerate
the golden file (set FUZZLAB_REGEN_GOLDEN=1) — a bare diff here is a red flag.
"""

import json
import os
from pathlib import Path

from fuzzlab.core.features import FEATURE_VERSION, Observation, extract

GOLDEN = Path(__file__).parent / "golden" / "features_v1.json"


def _cases():
    baseline = Observation(status=200, elapsed_ms=10.0,
                           body=b"<html><body>welcome</body></html>",
                           headers={})
    return {
        "sql_error": (
            Observation(status=500, elapsed_ms=12.0, body=b"", headers={}),
            Observation(status=500, elapsed_ms=12.0,
                        body=b"You have an error in your SQL syntax near ''",
                        headers={"Content-Type": "text/html"}),
            baseline,
        ),
        "benign_longer": (
            Observation(status=200, elapsed_ms=11.0, body=b"", headers={}),
            Observation(status=200, elapsed_ms=11.0,
                        body=b"<html><body>welcome back, user</body></html>",
                        headers={}),
            baseline,
        ),
        "no_baseline": (
            Observation(status=404, elapsed_ms=8.0, body=b"", headers={}),
            Observation(status=404, elapsed_ms=8.0, body=b"not found", headers={}),
            None,
        ),
    }


def _compute():
    return {
        name: extract(req, resp, base, version=FEATURE_VERSION)
        for name, (req, resp, base) in _cases().items()
    }


def test_features_match_golden():
    computed = _compute()
    if os.environ.get("FUZZLAB_REGEN_GOLDEN") == "1" or not GOLDEN.exists():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(computed, indent=2, sort_keys=True))
    expected = json.loads(GOLDEN.read_text())
    assert computed == expected


def test_no_payload_leak_in_features():
    # Same behavioral response, different "payload" strings -> identical features.
    resp = Observation(status=200, elapsed_ms=10.0, body=b"ok", headers={})
    a = extract(resp, resp, None)
    b = extract(resp, resp, None)
    assert a == b
