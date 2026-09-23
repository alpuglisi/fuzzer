"""Live-boot conformance check for PicTrail's `/explore` real page
(category 2 pilot, Phase C, `CC-LAB-0096`).

Real, on-host integration tests, same discipline as every other
`test_labgen_django_live_boot_*` module. Proves, for the first time in
this emitter, an identifier/`ORDER BY`-position SQLi (CWE-89) --
`lab/safety_matrix.yaml`'s own `sql_order_by_clause` sink family had no
real implementation on any stack before this entry.

The adversarial payload, `"id DESC"`, is deliberately **not** a syntax-
break payload (no quotes, no comment sequences) -- it is a real, legal
SQL fragment that only an *identifier/clause-position* injection can
exploit, proving this specific CWE-89 subtype rather than the ordinary
string-literal-escape shape already proven elsewhere in this project:

1. **Both directions of the differential** (`CC-LAB-0096`'s own risk
   section, per `PA-0034`): the vulnerable twin's raw concatenation
   genuinely lets `"id DESC"` reverse the real row order returned by a
   real SQLite query -- **and** the secure twin's `identifier_allowlist`
   genuinely ignores that same payload (it isn't a recognized allowlist
   key) and falls back to its own default ascending-by-`id` order,
   proven by comparing against a known-legitimate `sort=id` request, not
   merely asserting "it didn't error."
2. **Ground truth cross-check** (`PT-0005`, extending the same directory
   `CC-LAB-0092`/`CC-LAB-0093`/`CC-LAB-0094`/`CC-LAB-0095` established).
"""

from __future__ import annotations

import pytest

from fuzzlab.labels.contract import load as load_ground_truth
from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness, django_boot_available
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not django_boot_available(),
        reason=(
            "django live-boot harness requires python3/venv on PATH and real PyPI "
            "network reachability (PA-0005) -- see django_live_boot.django_boot_available()"
        ),
    ),
]

_GROUND_TRUTH_DIR = "lab/ground-truth-picktrail-django"
_MANIFEST_PATH = "lab/manifests/phase_c_picktrail_explore.yaml"
_PAYLOAD = "id DESC"
_ASCENDING_IDS = [1, 2]
_DESCENDING_IDS = [2, 1]


def test_vulnerable_twin_lets_the_payload_control_real_row_order() -> None:
    """A real, legal SQL fragment injected as the sort key (no quotes, no
    syntax break) must genuinely reverse the real row order a real
    SQLite query returns -- observed from the actual response body, not
    inferred from the absence of an error."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0015"]
    with DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.get("/explore", params={"sort": _PAYLOAD})

    assert resp.status == 200
    import json

    ids = [row["id"] for row in json.loads(resp.body)["results"]]
    assert ids == _DESCENDING_IDS, (
        f"the vulnerable twin must genuinely honor the injected ORDER BY modifier -- got {ids!r}"
    )


def test_secure_twin_ignores_the_payload_and_falls_back_to_the_default_order() -> None:
    """The identical payload against the secure twin must **not**
    reverse the order -- `identifier_allowlist` doesn't recognize
    `"id DESC"` as a key, so it falls back to `"id"`, producing the same
    ascending order a legitimate `sort=id` request would -- proven by
    comparing against that legitimate request directly, not merely
    asserting the response is 200."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0016"]
    with DjangoLiveBootHarness(emitter, secure_cells) as harness:
        resp_payload = harness.get("/generated/labgen_dj_0016/", params={"sort": _PAYLOAD})
        resp_legit = harness.get("/generated/labgen_dj_0016/", params={"sort": "id"})

    import json

    assert resp_payload.status == 200
    ids_payload = [row["id"] for row in json.loads(resp_payload.body)["results"]]
    ids_legit = [row["id"] for row in json.loads(resp_legit.body)["results"]]
    assert ids_payload == _ASCENDING_IDS == ids_legit, (
        "the secure twin must ignore the injected modifier and match a legitimate "
        f"sort=id request -- got payload={ids_payload!r}, legit={ids_legit!r}"
    )


def test_ground_truth_case_pt_0005_matches_the_real_served_page() -> None:
    """`PT-0005` names `GET /explore` as a real, exploitable identifier-
    position SQLi. Loaded independently (never re-deriving the URL from
    `DjangoEmitter`'s own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS`
    internals) and confirmed against a real booted request at exactly
    that URL, with the same adversarial payload the differential tests
    above use."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("PT-0005")
    assert case is not None, "PT-0005 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True
    assert case.vuln_class == "sqli"

    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0015"]
    with DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.request(case.method, case.url, params={case.param: _PAYLOAD})

    import json

    assert resp.status == 200
    ids = [row["id"] for row in json.loads(resp.body)["results"]]
    assert ids == _DESCENDING_IDS, (
        "the ground truth's own expected_vulnerable=true claim must hold at the exact "
        "URL/method/param it names"
    )
