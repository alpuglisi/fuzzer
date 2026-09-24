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
    assert len(gt.cases) == 11
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

    # CC-LAB-0187: Netflix's fourth real page, first access_control/IDOR
    # instance, /api/account/billing.
    billing_case = gt.case_by_id("NFLX-0004")
    assert billing_case is not None
    assert billing_case.expected_vulnerable
    assert billing_case.vuln_class == "access_control"
    assert billing_case.sink_context == "object_lookup"
    assert billing_case.url == "/api/account/billing"
    assert billing_case.method == "GET"
    assert billing_case.param == "account_id"
    assert billing_case.location == "query"

    # CC-LAB-0188: Netflix's fifth real page, first price_integrity_bypass
    # instance, /api/subscription/change-plan.
    price_case = gt.case_by_id("NFLX-0005")
    assert price_case is not None
    assert price_case.expected_vulnerable
    assert price_case.vuln_class == "price_integrity_bypass"
    assert price_case.sink_context == "payment_charge"
    assert price_case.url == "/api/subscription/change-plan"
    assert price_case.method == "POST"
    assert price_case.param == "body"
    assert price_case.location == "body"

    # CC-LAB-0191: Netflix's sixth real page, first unrestricted_file_upload
    # instance, /api/profiles/avatar.
    avatar_case = gt.case_by_id("NFLX-0006")
    assert avatar_case is not None
    assert avatar_case.expected_vulnerable
    assert avatar_case.vuln_class == "unrestricted_file_upload"
    assert avatar_case.sink_context == "fs_web_root_write"
    assert avatar_case.url == "/api/profiles/avatar"
    assert avatar_case.method == "POST"
    assert avatar_case.param == "file"
    assert avatar_case.location == "body"

    # CC-LAB-0192: Netflix's seventh real page, first mass_assignment
    # instance, /api/account/settings.
    settings_case = gt.case_by_id("NFLX-0007")
    assert settings_case is not None
    assert settings_case.expected_vulnerable
    assert settings_case.vuln_class == "mass_assignment"
    assert settings_case.sink_context == "mass_assignment"
    assert settings_case.url == "/api/account/settings"
    assert settings_case.method == "POST"
    assert settings_case.param == "body"
    assert settings_case.location == "body"

    # CC-LAB-0193: Netflix's eighth real page, first jwt_algorithm_confusion
    # instance, /api/account/preferences.
    jwt_case = gt.case_by_id("NFLX-0008")
    assert jwt_case is not None
    assert jwt_case.expected_vulnerable
    assert jwt_case.vuln_class == "jwt_algorithm_confusion"
    assert jwt_case.sink_context == "jwt"
    assert jwt_case.url == "/api/account/preferences"
    assert jwt_case.method == "GET"
    assert jwt_case.param == "Authorization"
    assert jwt_case.location == "header"

    # CC-LAB-0194: Netflix's ninth real page, first ssrf instance,
    # /api/content/thumbnail-import.
    ssrf_case = gt.case_by_id("NFLX-0009")
    assert ssrf_case is not None
    assert ssrf_case.expected_vulnerable
    assert ssrf_case.vuln_class == "ssrf"
    assert ssrf_case.sink_context == "network"
    assert ssrf_case.url == "/api/content/thumbnail-import"
    assert ssrf_case.method == "POST"
    assert ssrf_case.param == "thumbnail_url"
    assert ssrf_case.location == "query"

    # CC-LAB-0195: Netflix's tenth real page, first weak_token_entropy
    # instance, /api/session/refresh.
    token_case = gt.case_by_id("NFLX-0010")
    assert token_case is not None
    assert token_case.expected_vulnerable
    assert token_case.vuln_class == "weak_token_entropy"
    assert token_case.sink_context == "session_token"
    assert token_case.url == "/api/session/refresh"
    assert token_case.method == "POST"
    assert token_case.param == "body"
    assert token_case.location == "body"

    # CC-LAB-0197: Netflix's eleventh real page, first ssti/template_render
    # instance on this app identity, /api/support/template-preview.
    ssti_case = gt.case_by_id("NFLX-0011")
    assert ssti_case is not None
    assert ssti_case.expected_vulnerable
    assert ssti_case.vuln_class == "ssti"
    assert ssti_case.sink_context == "template"
    assert ssti_case.url == "/api/support/template-preview"
    assert ssti_case.method == "GET"
    assert ssti_case.param == "expr"
    assert ssti_case.location == "query"

    # Opaque case IDs: no vuln class leaks into the identifier.
    for case in gt.cases:
        for token in ("jackson", "deser", "vuln", "xxe", "idor", "access", "price", "charge",
                      "jwt", "confusion", "ssrf", "fetch", "token", "entropy", "ssti", "template"):
            assert token not in case.case_id.lower()


def test_twitch_ground_truth_loads_and_cross_checks():
    gt = contract.load(TWITCH_GT_DIR)
    assert gt.target == "go_net_http"
    assert len(gt.cases) == 15
    ids = {c.case_id for c in gt.cases}
    assert ids == {
        "TWCH-0001", "TWCH-0002", "TWCH-0003", "TWCH-0004", "TWCH-0005", "TWCH-0006",
        "TWCH-0007", "TWCH-0008", "TWCH-0009", "TWCH-0010", "TWCH-0011", "TWCH-0012",
        "TWCH-0013", "TWCH-0014", "TWCH-0015",
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

    emote_upload = gt.case_by_id("TWCH-0009")
    assert emote_upload.expected_vulnerable
    assert emote_upload.vuln_class == "unrestricted_file_upload"
    assert emote_upload.sink_context == "fs_web_root_write"
    assert emote_upload.url == "/generated/labgen-go-0017"
    assert emote_upload.method == "POST"
    assert emote_upload.param == "file"
    assert emote_upload.location == "body"

    price_integrity = gt.case_by_id("TWCH-0010")
    assert price_integrity.expected_vulnerable
    assert price_integrity.vuln_class == "price_integrity_bypass"
    assert price_integrity.sink_context == "payment_charge"
    assert price_integrity.url == "/generated/labgen-go-0019"
    assert price_integrity.method == "POST"
    assert price_integrity.param == "body"
    assert price_integrity.location == "body"

    # CC-LAB-0190: Twitch's 11th real page, first path_traversal/
    # fs_path_read instance on any stack.
    path_traversal = gt.case_by_id("TWCH-0011")
    assert path_traversal.expected_vulnerable
    assert path_traversal.vuln_class == "path_traversal"
    assert path_traversal.sink_context == "fs_path_read"
    assert path_traversal.url == "/generated/labgen-go-0021"
    assert path_traversal.method == "GET"
    assert path_traversal.param == "filename"
    assert path_traversal.location == "query"

    # CC-LAB-0196: Twitch's 12th real page, this stack's first
    # ssti/template_render instance (reuses an existing, multi-stack
    # concern -- genuinely new breadth, not a genuinely new mechanism).
    ssti = gt.case_by_id("TWCH-0012")
    assert ssti.expected_vulnerable
    assert ssti.vuln_class == "ssti"
    assert ssti.sink_context == "template"
    assert ssti.url == "/generated/labgen-go-0023"
    assert ssti.method == "POST"
    assert ssti.param == "body"
    assert ssti.location == "body"

    # CC-LAB-0198: Twitch's 13th real page, this project's first
    # http_header_injection/http_response_header_value instance on any
    # stack.
    header_injection = gt.case_by_id("TWCH-0013")
    assert header_injection.expected_vulnerable
    assert header_injection.vuln_class == "http_header_injection"
    assert header_injection.sink_context == "header"
    assert header_injection.url == "/generated/labgen-go-0025"
    assert header_injection.method == "GET"
    assert header_injection.param == "destination"
    assert header_injection.location == "query"

    # CC-LAB-0199: Twitch's 14th real page, this stack's first
    # open_redirect/http_redirect_location instance (reuses an existing,
    # multi-stack concern from php_laravel's Booking.com pilot -- genuinely
    # new breadth, not a genuinely new mechanism).
    open_redirect = gt.case_by_id("TWCH-0014")
    assert open_redirect.expected_vulnerable
    assert open_redirect.vuln_class == "open_redirect"
    assert open_redirect.sink_context == "redirect"
    assert open_redirect.url == "/generated/labgen-go-0027"
    assert open_redirect.method == "GET"
    assert open_redirect.param == "next"
    assert open_redirect.location == "query"

    # CC-LAB-0199/BUG-0045: Twitch's 15th real case is NOT a new page -- it
    # is a second, honest vuln_class label at TWCH-0013's own url/param
    # (/generated/labgen-go-0025?destination=), found empirically once
    # open_redirect's runmode category mapping made it reachable: that
    # sink is genuinely ALSO open-redirect-vulnerable (a plain external
    # `destination` needs no CRLF at all), not just http_header_injection.
    second_label = gt.case_by_id("TWCH-0015")
    assert second_label.expected_vulnerable
    assert second_label.vuln_class == "open_redirect"
    assert second_label.sink_context == "redirect"
    assert second_label.url == "/generated/labgen-go-0025"
    assert second_label.method == "GET"
    assert second_label.param == "destination"
    assert second_label.location == "query"

    for case in gt.cases:
        for token in ("webhook", "ssrf", "vuln", "idor", "access", "jwt", "entropy", "mass", "upload",
                      "price", "charge", "traversal", "path", "ssti", "template", "header", "injection",
                      "redirect", "crlf"):
            assert token not in case.case_id.lower()


def test_default_ground_truth_unaffected_by_schema_widening():
    # The labels.schema.json vuln_class/sink_context widening (CC-LAB-0174)
    # is additive-only; the default lab's own ground truth must still load
    # and validate exactly as before.
    gt = contract.load("lab/ground-truth")
    assert gt.target == "php_laravel"
    assert len(gt.positives()) == 8
