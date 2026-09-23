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
    assert len(gt.cases) == 3
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

    # CC-LAB-0184: second insecure_deserialization instance, /api/profiles/switch.
    profiles_case = gt.case_by_id("NFLX-0003")
    assert profiles_case is not None
    assert profiles_case.expected_vulnerable
    assert profiles_case.vuln_class == "insecure_deserialization"
    assert profiles_case.sink_context == "deserialization"
    assert profiles_case.url == "/api/profiles/switch"
    assert profiles_case.method == "POST"
    assert profiles_case.param == "body"
    assert profiles_case.location == "body"

    # Opaque case IDs: no vuln class leaks into the identifier.
    for case in gt.cases:
        for token in ("jackson", "deser", "vuln", "xxe"):
            assert token not in case.case_id.lower()


def test_twitch_ground_truth_loads_and_cross_checks():
    gt = contract.load(TWITCH_GT_DIR)
    assert gt.target == "go_net_http"
    assert len(gt.cases) == 8
    ids = {c.case_id for c in gt.cases}
    assert ids == {
        "TWCH-0001", "TWCH-0002", "TWCH-0003", "TWCH-0004", "TWCH-0005", "TWCH-0006",
        "TWCH-0007", "TWCH-0008",
    }

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

    weak_token = gt.case_by_id("TWCH-0005")
    assert weak_token.expected_vulnerable
    assert weak_token.vuln_class == "weak_token_entropy"
    assert weak_token.sink_context == "session_token"
    assert weak_token.url == "/generated/labgen-go-0009"
    assert weak_token.method == "POST"
    assert weak_token.param == "body"
    assert weak_token.location == "body"

    mass_assignment = gt.case_by_id("TWCH-0006")
    assert mass_assignment.expected_vulnerable
    assert mass_assignment.vuln_class == "mass_assignment"
    assert mass_assignment.sink_context == "mass_assignment"
    assert mass_assignment.url == "/generated/labgen-go-0011"
    assert mass_assignment.method == "POST"
    assert mass_assignment.param == "body"
    assert mass_assignment.location == "body"

    subscribers_idor = gt.case_by_id("TWCH-0007")
    assert subscribers_idor.expected_vulnerable
    assert subscribers_idor.vuln_class == "access_control"
    assert subscribers_idor.sink_context == "object_lookup"
    assert subscribers_idor.url == "/generated/labgen-go-0013"
    assert subscribers_idor.method == "GET"
    assert subscribers_idor.param == "channel_id"
    assert subscribers_idor.location == "query"

    clips_download_ssrf = gt.case_by_id("TWCH-0008")
    assert clips_download_ssrf.expected_vulnerable
    assert clips_download_ssrf.vuln_class == "ssrf"
    assert clips_download_ssrf.sink_context == "network"
    assert clips_download_ssrf.url == "/generated/labgen-go-0015"
    assert clips_download_ssrf.method == "GET"
    assert clips_download_ssrf.param == "source_url"
    assert clips_download_ssrf.location == "query"

    for case in gt.cases:
        for token in ("webhook", "ssrf", "vuln", "idor", "access", "jwt", "entropy", "mass"):
            assert token not in case.case_id.lower()


def test_default_ground_truth_unaffected_by_schema_widening():
    # The labels.schema.json vuln_class/sink_context widening (CC-LAB-0174)
    # is additive-only; the default lab's own ground truth must still load
    # and validate exactly as before.
    gt = contract.load("lab/ground-truth")
    assert gt.target == "php_laravel"
    assert len(gt.positives()) == 8
