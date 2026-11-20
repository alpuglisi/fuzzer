"""PA-0114 / PA-0681: OWASP crAPI's state switches and destructive actions, enumerated
from its source at v1.1.6 (commit 700f03d1) before its first crawl and judged by the
real gates (CC-LAB-0437).

Each row names what the route changes (file:line in upstream's tree), the gate that
must stop it and the expectation; the test computes the gate's verdict (PA-0001,
PA-0301(3)). A route no gate refuses is a ``residual`` with its compensating control,
pinned to None so the row is revisited when a rule starts refusing it.

Gates (as `tests/test_destructive_routes_external_labs.py` defines them, plus disco's):

* ``visit``        -- `core.urls.destructive_reason` (SP-09) on the URL;
* ``request``      -- `store_adapter.request_refusal`: a captured request's method and
  URL (destructive and transaction rules, DELETE never, PUT only with
  ``--fuzz-json-writes``);
* ``body``         -- `store_adapter.captured_request`: a captured JSON body (the
  credential-change rule, SP-120's settings words, destructive entries);
* ``spa-form``     -- `tools.spa.form_refusal` (the legacy spider's SPA forms);
* ``disco-click``  -- `disco.explore.refusal` (an element's label / name / link);
* ``disco-form``   -- `disco.explore.form_refusal` (a form disco would submit).

crAPI's logout is client-side only (navBar.tsx:62 clears localStorage; no server route),
so its row is the menu item's label.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

import pytest

from fuzzlab.core.urls import destructive_reason
from fuzzlab.disco import explore
from fuzzlab.tools import spa
from fuzzlab.tools.store_adapter import captured_request, request_refusal

#: The rows cite upstream's tree at the v1.1.6 tag (identity's files under
#: services/identity/src/main/java/com/crapi/).
CRAPI = "http://127.0.0.1:3101"


def _req(method: str, path: str) -> Callable[[], str | None]:
    return lambda: request_refusal(method, CRAPI + path)


def _body(method: str, path: str, body: dict) -> Callable[[], str | None]:
    row = {"method": method, "url": CRAPI + path, "content_type": "application/json",
           "body_json": json.dumps(body), "page_url": CRAPI + "/"}
    return lambda: captured_request(row)[0]


def _spa(route: str, controls, button: str) -> Callable[[], str | None]:
    form = {"controls": controls, "button": button, "button_aria": "", "action": None}
    return lambda: spa.form_refusal(form, route, named=None)


def _click(label: str) -> Callable[[], str | None]:
    return lambda: explore.refusal({"label": label}, ())


def _dform(fields, label: str) -> Callable[[], str | None]:
    return lambda: explore.form_refusal(
        [{"name": n, "type": t} for n, t in fields], {"label": label, "action": ""})


@dataclass(frozen=True)
class Row:
    method: str
    path: str
    effect: str        # what it changes, with upstream's file:line
    gate: str
    verdict: Callable[[], str | None]
    expect: str        # "refused" or "residual: <compensating control>"


_PW2 = [("password", "password"), ("againPassword", "password")]

ROWS = [
    Row("POST", "/identity/api/v2/user/reset-password",
        "sets the bearer's password (UserController.java:58)", "visit",
        lambda: destructive_reason(CRAPI + "/identity/api/v2/user/reset-password"), "refused"),
    Row("POST", "/identity/api/v2/user/reset-password",
        "the SPA route /reset-password that sends it (layout.tsx:260)", "spa-form",
        _spa("reset-password", _PW2, "Change Password"), "refused"),
    Row("POST", "/identity/api/v2/user/reset-password",
        "its form as disco sees it (resetPassword.tsx: two password controls)",
        "disco-form", _dform(_PW2, "Change Password"), "refused"),
    Row("POST", "/identity/api/auth/reset-test-users",
        "resets the seeded users' passwords (AuthController.java:180)", "request",
        _req("POST", "/identity/api/auth/reset-test-users"), "refused"),
    Row("POST", "/identity/api/auth/v2/check-otp",
        "sets a password from a mailed OTP, no attempt limit (AuthController.java:126)",
        "disco-form", _dform([("otp", "text"), *_PW2], "Reset Password"), "refused"),
    Row("POST", "/identity/api/auth/v2/check-otp",
        "the same form on the legacy spider (otpForm.tsx)", "spa-form",
        _spa("forgot-password", [("otp", "text"), *_PW2], "Reset Password"), "refused"),
    Row("POST", "/identity/api/auth/v2/check-otp",
        "a captured check-otp body (email, otp, password)", "body",
        _body("POST", "/identity/api/auth/v2/check-otp",
              {"email": "a@example.com", "otp": "0000", "password": "x"}),
        "residual: only captured if its form is submitted (refused above); a fuzzed "
        "value is never the mailed 4-digit OTP, and the email is the crawler's filler"),
    Row("POST", "/identity/api/auth/forget-password",
        "mails an OTP to an address (AuthController.java:111)", "spa-form",
        _spa("forgot-password", [("email", "text")], "Send OTP"),
        "residual: mails a code into the lab's own mailhog; changes no account"),
    Row("POST", "/identity/api/auth/signup", "creates an account (AuthController.java:71)",
        "body", _body("POST", "/identity/api/auth/signup",
                      {"name": "a", "email": "a@example.com", "number": "1",
                       "password": "x"}), "refused"),
    Row("POST", "/identity/api/auth/signup", "the signup form (signup.tsx)", "disco-form",
        _dform([("email", "text"), *_PW2], "Signup"), "refused"),
    Row("POST", "/identity/api/v2/user/change-email",
        "files an email change, applied only with the token mailed to the new address "
        "(ChangeEmailController.java:41/59)", "spa-form",
        _spa("change-email", [("email", "text"), ("new_email", "text")], "Send Token"),
        "residual: the change needs the mailed token (verify-email-token), which no "
        "crawler reads; its verify form is refused (next row)"),
    Row("POST", "/identity/api/v2/user/verify-email-token",
        "applies the email change (ChangeEmailController.java:59)", "spa-form",
        _spa("change-email", [("token", "text"), ("password", "password")], "Verify"),
        "refused"),
    Row("POST", "/identity/api/v2/user/change-phone-number",
        "files a number change, applied only with a mailed OTP "
        "(ChangePhoneController.java:26/44)", "spa-form",
        _spa("change-phone-number", [("phone_number", "text"), ("new_number", "text")],
             "Send OTP"),
        "residual: the change needs the mailed OTP; its verify form is refused (next row)"),
    Row("POST", "/identity/api/v2/user/verify-phone-otp",
        "applies the number change", "spa-form",
        _spa("change-phone-number", [("otp", "text"), ("password", "password")],
             "Verify"), "refused"),
    Row("DELETE", "/identity/api/v2/user/videos/1",
        "deletes the bearer's video (ProfileController.java:113)", "request",
        _req("DELETE", "/identity/api/v2/user/videos/1"), "refused"),
    Row("DELETE", "/identity/api/v2/admin/videos/1",
        "deletes any user's video, no role check (ProfileController.java:129, BFLA)",
        "request", _req("DELETE", "/identity/api/v2/admin/videos/1"), "refused"),
    Row("DELETE", "/identity/api/v2/user/videos/1", "the profile's Delete Video button",
        "disco-click", _click("Delete Video"), "refused"),
    Row("PUT", "/identity/api/v2/user/videos/1",
        "renames the video and binds conversion_params (ProfileController.java:95)",
        "request", _req("PUT", "/identity/api/v2/user/videos/1"), "refused"),
    Row("POST", "/identity/api/v2/user/videos",
        "uploads a video (ProfileController.java:78)", "spa-form",
        _spa("my-profile", [("file", "file")], "Upload"), "refused"),
    Row("GET", "/identity/api/v2/user/videos/convert_video?video_id=1",
        "runs a shell command only with ENABLE_SHELL_INJECTION=true "
        "(ProfileServiceImpl; BashCommand.java)", "request",
        _req("GET", "/identity/api/v2/user/videos/convert_video?video_id=1"),
        "residual: the fixture keeps ENABLE_SHELL_INJECTION=false (upstream's default): "
        "the route only answers a message"),
    Row("POST", "/identity/management/admin/lockUser",
        "locks any account (ManagementControlller.java:48)", "request",
        _req("POST", "/identity/management/admin/lockUser"),
        "residual: hasRole(ADMIN) (WebSecurityConfig.java:89); the run's accounts are "
        "ROLE_USER and no page links it"),
    Row("POST", "/identity/api/v2/vehicle/add_vehicle",
        "adds a vehicle from a mailed VIN and pincode (VehicleController.java:47)",
        "spa-form", _spa("verify-vehicle", [("vin", "text"), ("pinCode", "text")],
                         "Verify"),
        "residual: a filler VIN matches no mailed vehicle; nothing is added"),
    Row("GET", "/", "the navbar's Logout item (navBar.tsx:108): clears the token",
        "disco-click", _click("Logout"), "refused"),
    Row("POST", "/workshop/api/shop/orders",
        "buys a product, spending credit (shop/views.py:168)", "request",
        _req("POST", "/workshop/api/shop/orders"), "refused"),
    Row("POST", "/workshop/api/shop/orders", "the shop's Buy button (shop.tsx)",
        "disco-click", _click("Buy"),
        "residual (gap, CC-LAB-0437): disco's element rule reads destructive words only, "
        "not transaction words; a click spends the run's own account's credit (10 per "
        "order, refused below 10: shop/views.py:195), and the lab is reset per run"),
    Row("PUT", "/workshop/api/shop/orders/1",
        "sets an order's status; `returned` refunds it (shop/views.py:219, mass "
        "assignment)", "request", _req("PUT", "/workshop/api/shop/orders/1"), "refused"),
    Row("POST", "/workshop/api/shop/orders/return_order?order_id=1",
        "marks an own order return-pending (shop/views.py:303)", "request",
        _req("POST", "/workshop/api/shop/orders/return_order?order_id=1"), "refused"),
    Row("POST", "/workshop/api/shop/apply_coupon",
        "adds a coupon's amount to the credit, once per code (shop/views.py:366)",
        "body", _body("POST", "/workshop/api/shop/apply_coupon",
                      {"coupon_code": "TRAC075", "amount": 75}),
        "residual: a ground-truth point (SQL injection); credit rises only for a code "
        "MongoDB holds, which a payload is not"),
    Row("POST", "/workshop/api/shop/apply_coupon", "the shop's coupon form (shop.tsx)",
        "spa-form", _spa("shop", [("couponCode", "text")], "Validate"), "refused"),
    Row("POST", "/community/api/v2/coupon/new-coupon",
        "creates a coupon (coupon_controller.go:31)", "request",
        _req("POST", "/community/api/v2/coupon/new-coupon"),
        "residual: no page sends it; a row in the lab's MongoDB"),
    Row("POST", "/workshop/api/shop/products", "adds a shop product (shop/views.py:83)",
        "request", _req("POST", "/workshop/api/shop/products"),
        "residual: no page sends it; a row in the lab's database"),
    Row("POST", "/workshop/api/merchant/contact_mechanic",
        "fetches mechanic_api, repeating up to 100 times (merchant/views.py:46-127)",
        "body", _body("POST", "/workshop/api/merchant/contact_mechanic",
                      {"mechanic_code": "TRAC_JHN", "problem_details": "p", "vin": "v",
                       "mechanic_api": CRAPI + "/workshop/api/mechanic/receive_report",
                       "repeat_request_if_failed": False, "number_of_repeats": 1}),
        "residual: a ground-truth point (SSRF); the workshop sits on an internal "
        "network (no egress), repeats are capped at 100 upstream, booleans are not "
        "fuzzed (FR-AUD-601)"),
    Row("GET", "/workshop/api/mechanic/receive_report?mechanic_code=m&problem_details=p"
        "&vin=v", "creates a service request on a GET (mechanic/views.py:169)", "request",
        _req("GET", "/workshop/api/mechanic/receive_report?mechanic_code=m"
             "&problem_details=p&vin=v"),
        "residual: no page links it (only contact_mechanic's server-side call); a row"),
    Row("POST", "/identity/api/auth/login", "issues a JWT (AuthController.java:55)",
        "disco-form", _dform([("email", "email"), ("password", "password")], "Login"),
        "residual: a filler login is refused (401) and changes nothing; no lockout "
        "exists (UserServiceImpl.java:85-120)"),
    Row("POST", "/community/api/v2/coupon/validate-coupon",
        "looks a coupon up, read-only (coupon_controller.go:63)", "disco-form",
        _dform([("couponCode", "text")], "Validate"),
        "residual: read-only (FindOne); the shop's apply call follows only a valid code"),
    Row("POST", "/community/api/v2/community/posts", "creates a forum post", "spa-form",
        _spa("new-post", [("title", "text"), ("content", "textarea")], "Post"),
        "residual: row creation, the stored-XSS negative's own store"),
]


@pytest.mark.parametrize("row", ROWS, ids=lambda r: f"{r.gate}:{r.method}:{r.path}")
def test_each_crapi_state_switch_gets_its_gates_actual_verdict(row):
    verdict = row.verdict()
    if row.expect == "refused":
        assert verdict is not None, f"{row.path}: the {row.gate} gate let it through"
    else:
        assert row.expect.startswith("residual") and len(row.expect) > 30
        assert verdict is None, (f"{row.path} is now refused by {row.gate} ({verdict!r}): "
                                 "move it from the residuals to 'refused'")


def test_the_crapi_table_covers_every_state_changing_route_of_the_answer_key():
    """Every non-GET point of lab/ground-truth-crapi/ is a row (PA-0114(1)): a scored
    write is enumerated, never discovered by the crawl first."""
    from pathlib import Path
    key = Path(__file__).resolve().parent.parent / "lab/ground-truth-crapi/labels.json"
    cases = json.loads(key.read_text())["cases"]
    writes = {(c["method"], c["url"].split("?", 1)[0]) for c in cases if c["method"] != "GET"}
    rows = {(r.method, r.path.split("?", 1)[0]) for r in ROWS}
    assert writes and writes <= rows, sorted(writes - rows)
