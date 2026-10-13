"""Candidate features live in `core/`'s versioned feature store (FR-ML-5, CC-CORE-0031).

The golden vectors were captured from `fuzzlab.ml.dataset._features` **before** the
extractor moved to `fuzzlab.core.features`; the move must leave every vector, the name
order and the version exactly as they were (feature-store discipline), so every saved
model and `check_compatible` is unaffected.
"""

from __future__ import annotations

import json
from pathlib import Path

from fuzzlab.core import features as core_features
from fuzzlab.ml import dataset

GOLDEN = json.loads((Path(__file__).parent / "data" / "candidate_features" /
                     "v1_golden.json").read_text())


def test_vectors_match_the_pre_move_golden_file():
    assert len(GOLDEN["cases"]) >= 10
    for case in GOLDEN["cases"]:
        args = (case["evidence"], case["sink_context"], case["rules_fired"])
        assert core_features.extract_candidate_v1(*args) == case["vector"]
        assert dataset._features(*args) == case["vector"]


def test_names_and_version_are_unchanged_and_shared():
    assert core_features.CANDIDATE_FEATURE_NAMES == GOLDEN["feature_names"]
    assert dataset.FEATURE_NAMES == GOLDEN["feature_names"]
    assert core_features.CANDIDATE_FEATURE_VERSION == dataset.FEATURE_VERSION == \
        GOLDEN["feature_version"] == 1
    # the response-behaviour extractor keeps its own, independent counter
    assert core_features.FEATURE_VERSION == 1


def test_core_features_never_import_ml():
    import ast
    tree = ast.parse(Path(core_features.__file__).read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | \
        {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m and m.startswith("fuzzlab.ml") for m in mods)
