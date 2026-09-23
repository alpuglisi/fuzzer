"""Live-boot conformance check for `django` Phase B (category 2 pilot,
`CC-LAB-0091`).

Real, on-host integration tests -- same discipline as
`test_labgen_django_live_boot_single_shape.py` (Phase A's own module):
real `venv`, real `pip install django==<pinned>`, real `manage.py migrate`/
`runserver`, real HTTP requests, torn down on every exit path. Proves the
two shapes Phase B added:

- `sqli`/`sql_string_literal` (`/api/login`, POST): a real SQLi-bypass-vs-
  safely-bound differential against a real seeded `users` row.
- `xss`/`html_body` (`/api/profile`, GET): a real raw-vs-escaped
  differential against a real seeded `profiles` row (`DjangoLiveBootHarness`'s
  `seed_bio` constructor parameter, added for exactly this proof).

Also the `PA-0034` adversarial test `CC-LAB-0091`'s own pre-change review
required: a mismatched-HTTP-method request against the newly
`@csrf_exempt`-decorated `/api/login` view, confirming the exemption does
not silently widen the attack surface beyond the labeled SQLi shape.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.django_live_boot import (
    SEED_PASSWORD,
    SEED_USERNAME,
    DjangoLiveBootHarness,
    django_boot_available,
)
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

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

_LOGIN_ROUTE = Route(method="POST", path="/api/login")
_LOGIN_SINK_CONTEXT = SinkContext(family="sql_string_literal", required_neutralizations=("sql_syntax_break",))

_PROFILE_ROUTE = Route(method="GET", path="/api/profile")
_PROFILE_SINK_CONTEXT = SinkContext(family="html_body", required_neutralizations=("html_tag_break",))

_XSS_PAYLOAD = "<script>alert(1)</script>"


def _vuln_login_cell() -> Cell:
    return Cell(
        cell_id="LABGEN-DJ-0003",
        vuln_class="sqli",
        stack_profile="django",
        route=_LOGIN_ROUTE,
        sink_context=_LOGIN_SINK_CONTEXT,
        transform=Pipeline(ops=()),
    )


def _secure_login_cell() -> Cell:
    return Cell(
        cell_id="LABGEN-DJ-0004",
        vuln_class="sqli",
        stack_profile="django",
        route=_LOGIN_ROUTE,
        sink_context=_LOGIN_SINK_CONTEXT,
        transform=Pipeline(ops=("param_bind",)),
    )


def _vuln_profile_cell() -> Cell:
    return Cell(
        cell_id="LABGEN-DJ-0005",
        vuln_class="xss",
        stack_profile="django",
        route=_PROFILE_ROUTE,
        sink_context=_PROFILE_SINK_CONTEXT,
        transform=Pipeline(ops=()),
    )


def _secure_profile_cell() -> Cell:
    return Cell(
        cell_id="LABGEN-DJ-0006",
        vuln_class="xss",
        stack_profile="django",
        route=_PROFILE_ROUTE,
        sink_context=_PROFILE_SINK_CONTEXT,
        transform=Pipeline(ops=("html_entity_escape",)),
    )


def test_login_normal_credentials_both_twins() -> None:
    """A real, legitimate login returns the real seeded row on both twins."""
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, [_vuln_login_cell(), _secure_login_cell()]) as harness:
        vuln_resp = harness.post(
            "/generated/labgen_dj_0003/", data={"username": SEED_USERNAME, "password": SEED_PASSWORD}
        )
        secure_resp = harness.post(
            "/generated/labgen_dj_0004/", data={"username": SEED_USERNAME, "password": SEED_PASSWORD}
        )

    assert vuln_resp.status == 200
    assert secure_resp.status == 200


def test_login_sqli_bypass_payload_differential() -> None:
    """The real payload differential: the vulnerable twin's unparameterized,
    quoted-string-concatenated query is broken by a classic
    `' OR '1'='1` SQLi-login-bypass payload -- SQLite executes the doctored
    query and returns the real seeded row with **no** correct password
    required (a real, observable authentication bypass: 200, not 404). The
    secure twin's parameterized `%s` placeholders treat the exact same
    payload as literal, non-matching string values (a real 404 -- no
    bypass)."""
    emitter = DjangoEmitter()
    # `' OR 1=1` alone is not enough here: the trailing literal
    # `" AND password = '<hash>'"` the sink appends still ANDs against it
    # (SQL operator precedence -- AND binds tighter than OR), so the
    # password check would still apply unless it's commented out. A real
    # `--` SQL comment (SQLite honors it) strips the rest of the statement,
    # the textbook login-bypass shape this cell exists to prove.
    bypass_username = "' OR 1=1 -- "
    with DjangoLiveBootHarness(emitter, [_vuln_login_cell(), _secure_login_cell()]) as harness:
        vuln_resp = harness.post(
            "/generated/labgen_dj_0003/", data={"username": bypass_username, "password": "wrong-password"}
        )
        secure_resp = harness.post(
            "/generated/labgen_dj_0004/", data={"username": bypass_username, "password": "wrong-password"}
        )

    assert vuln_resp.status == 200, "expected the real SQLi auth-bypass to succeed on the vulnerable twin"
    assert secure_resp.status == 404, "the secure twin must not be bypassed by the same payload"


def test_login_mismatched_http_method_does_not_widen_attack_surface() -> None:
    """`PA-0034` (`CC-LAB-0091`'s pre-change review): an adversarial input
    *orthogonal* to the feature's own demonstration -- here, a mismatched
    HTTP method (`GET` instead of `POST`) against the newly
    `@csrf_exempt`-decorated `/api/login` view. Confirms the CSRF exemption
    does not silently widen the attack surface: Django's `request.POST` on
    a `GET` request is an empty `QueryDict`, so the expected, verified
    behavior is "no row matches" (a real 404) -- never an unhandled
    exception (a 500) and never an unintended bypass (a 200)."""
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, [_vuln_login_cell()]) as harness:
        resp = harness.get(
            "/generated/labgen_dj_0003/", params={"username": SEED_USERNAME, "password": SEED_PASSWORD}
        )

    assert resp.status == 404, (
        "a GET against the CSRF-exempt login view must not crash (500) or bypass (200) -- "
        "request.POST must be empty on a GET request"
    )


def test_stored_xss_raw_vs_escaped_differential() -> None:
    """The real payload differential for the stored-XSS shape: seeding the
    `profiles` row with a real `<script>` payload (`DjangoLiveBootHarness`'s
    `seed_bio` constructor parameter), the vulnerable twin's raw string
    concatenation into the `HttpResponse` body serves the payload
    **unescaped** (a real, observable stored-XSS sink), while the secure
    twin's `django.utils.html.escape()` transform serves the real HTML-
    entity-escaped form."""
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, [_vuln_profile_cell()], seed_bio=_XSS_PAYLOAD) as harness:
        vuln_resp = harness.get("/generated/labgen_dj_0005/")
    with DjangoLiveBootHarness(emitter, [_secure_profile_cell()], seed_bio=_XSS_PAYLOAD) as harness:
        secure_resp = harness.get("/generated/labgen_dj_0006/")

    assert vuln_resp.status == 200
    assert _XSS_PAYLOAD in vuln_resp.body, "vulnerable twin must serve the raw, unescaped payload"
    assert secure_resp.status == 200
    assert _XSS_PAYLOAD not in secure_resp.body, "secure twin must not serve the raw payload"
    assert "&lt;script&gt;" in secure_resp.body, "secure twin must serve the real HTML-entity-escaped form"
