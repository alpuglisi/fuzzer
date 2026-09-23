"""Ground-truth contract tests for category 4's Netflix and Twitch clones
(CC-LAB-0174/FR-LAB-80). Mirrors tests/test_labels_contract.py's own pattern
of asserting concrete content, not just that contract.load() doesn't raise --
a bare load-succeeds smoke test would not catch a wrong case count, a wrong
param, or a vuln_class typo, which is exactly the kind of regression this
contract exists to catch.
"""

from fuzzlab.labels import contract

NETFLIX_GT_DIR = "lab/ground-truth-netflix-clone"
TWITCH_GT_DIR = "lab/ground-truth-twitch-clone"


def test_netflix_ground_truth_loads_and_cross_checks():
    gt = contract.load(NETFLIX_GT_DIR)
    assert gt.target == "spring_boot"
    assert len(gt.cases) == 2
    case = gt.case_by_id("NFLX-0001")
    assert case is not None
    assert case.expected_vulnerable
    assert case.vuln_class == "insecure_deserialization"
    assert case.sink_context == "deserialization"
    assert case.url == "/api/playback/resume"
    assert case.method == "POST"
    assert case.param == "body"
    assert case.location == "body"

    xxe_case = gt.case_by_id("NFLX-0002")
    assert xxe_case is not None
    assert xxe_case.expected_vulnerable
    assert xxe_case.vuln_class == "xxe"
    assert xxe_case.sink_context == "xml"
    assert xxe_case.url == "/api/content/import"
    assert xxe_case.method == "POST"
    assert xxe_case.param == "body"
    assert xxe_case.location == "body"

    # Opaque case IDs: no vuln class leaks into the identifier.
    for case in gt.cases:
        for token in ("jackson", "deser", "vuln", "xxe"):
            assert token not in case.case_id.lower()


def test_twitch_ground_truth_loads_and_cross_checks():
    gt = contract.load(TWITCH_GT_DIR)
    assert gt.target == "go_net_http"
    assert len(gt.cases) == 4
    ids = {c.case_id for c in gt.cases}
    assert ids == {"TWCH-0001", "TWCH-0002", "TWCH-0003", "TWCH-0004"}

    webhook = gt.case_by_id("TWCH-0001")
    assert webhook.expected_vulnerable
    assert webhook.vuln_class == "webhook_signature"
    assert webhook.sink_context == "webhook"
    assert webhook.url == "/generated/labgen-go-0001"
    assert webhook.method == "POST"
    assert webhook.param == "X-Signature-256"
    assert webhook.location == "header"

    ssrf = gt.case_by_id("TWCH-0002")
    assert ssrf.expected_vulnerable
    assert ssrf.vuln_class == "ssrf"
    assert ssrf.sink_context == "network"
    assert ssrf.url == "/generated/labgen-go-0003"
    assert ssrf.method == "GET"
    assert ssrf.param == "url"
    assert ssrf.location == "query"

    idor = gt.case_by_id("TWCH-0003")
    assert idor.expected_vulnerable
    assert idor.vuln_class == "access_control"
    assert idor.sink_context == "object_lookup"
    assert idor.url == "/generated/labgen-go-0005"
    assert idor.method == "GET"
    assert idor.param == "channel_id"
    assert idor.location == "query"

    jwt = gt.case_by_id("TWCH-0004")
    assert jwt.expected_vulnerable
    assert jwt.vuln_class == "jwt_algorithm_confusion"
    assert jwt.sink_context == "jwt"
    assert jwt.url == "/generated/labgen-go-0007"
    assert jwt.method == "GET"
    assert jwt.param == "Authorization"
    assert jwt.location == "header"

    for case in gt.cases:
        for token in ("webhook", "ssrf", "vuln", "idor", "access", "jwt"):
            assert token not in case.case_id.lower()


def test_default_ground_truth_unaffected_by_schema_widening():
    # The labels.schema.json vuln_class/sink_context widening (CC-LAB-0174)
    # is additive-only; the default lab's own ground truth must still load
    # and validate exactly as before.
    gt = contract.load("lab/ground-truth")
    assert gt.target == "php_laravel"
    assert len(gt.positives()) == 8
