"""PA-0114 / PA-0301: every lab's destructive or state-rewriting routes, judged by the
real gates.

BUG-0301: the destructive rule (`core.urls.destructive_reason`) does not refuse Juice
Shop's ``GET /rest/user/change-password?current=&new=&repeat=`` (it changes the bearer's
password; ``current`` is optional server-side, so a replayed URL changes it) nor
``/dataerasure`` (one token ``dataerasure``; its server-rendered form passes
`store_adapter.form_skip_reason`, so the POST would be imported and fuzzed). Both are
pinned below as strict xfails (PA-0054(3)); the corrective action belongs to the owner
of the locked ``fuzzlab/core/urls.py`` (CC-CORE-0301).

Each table row names the gate that must stop the route, and the test computes that
gate's verdict (PA-0001, PA-0027(b)) -- nothing is hand-asserted where the code can
compute it:

* ``visit``    -- the crawler's link gate: `core.urls.destructive_reason`;
* ``request``  -- a captured or imported request: `store_adapter.request_refusal`
  (destructive and transaction URL rules, the DELETE / PUT / PATCH method gate);
* ``body``     -- a captured request's body: `store_adapter.captured_request`;
* ``form``     -- a crawled server-rendered form: `store_adapter.form_skip_reason`, on
  the app's own markup;
* ``spa-form`` -- a single-page app form the crawler would submit:
  `spa.form_refusal` then `spa.captcha_reason`, as the spider calls them.

A route no gate refuses is listed as a ``residual`` with what it changes and why that
is accepted, and its verdict is pinned to None so the row is revisited the day a rule
starts refusing it (as `test_forms_phase1.BWAPP_NOT_URL_CAUGHT` does).

PA-0301's mechanical half: `test_no_lab_route_hides_a_destructive_word_in_a_compound`
scans every enumerated route of every lab (Juice Shop, bWAPP, and the generated labs'
manifests and ground truth) for a destructive or transaction word inside a longer
token (``dataerasure``) and for a credential verb-object pair (``change-password``,
``password_change``); each hit the rule does not already refuse needs a disposition
here. It is proven on synthetic offenders (PA-0034(2)).
"""

from __future__ import annotations

import glob
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from bs4 import BeautifulSoup

from fuzzlab.core.forms import form_record
from fuzzlab.core.urls import (
    DESTRUCTIVE_TOKENS,
    TRANSACTION_TOKENS,
    DestructiveUrlRefused,
    _url_tokens,
    check_send_url,
    destructive_reason,
    transaction_reason,
)
from fuzzlab.tools import spa
from fuzzlab.tools.store_adapter import (
    _object_selector,
    captured_request,
    form_skip_reason,
    request_refusal,
)

ROOT = Path(__file__).resolve().parents[1]
JUICE = "http://127.0.0.1:3000"
BWAPP = "http://127.0.0.1:8092"


def _form(html: str, page: str) -> dict:
    """The app's real form markup -> the dict `store_adapter._import_forms` judges (the
    spider stores `core.forms.form_record`; the importer reads its lists back as
    tuples)."""
    rec = form_record(BeautifulSoup(html, "html.parser").find("form"), page)
    return {"action_url": rec["action_url"], "method": rec["method"],
            "enctype": rec["enctype"], "entries": [tuple(e) for e in rec["entries"]],
            "controls": [tuple(c) for c in rec["controls"]], "selector": rec["selector"],
            "options": rec["options"]}


def _captured(method: str, url: str, content_type: str | None, body: dict | None,
              page: str) -> str | None:
    row = {"method": method, "url": url, "content_type": content_type,
           "body_json": json.dumps(body) if body is not None else None, "page_url": page}
    return captured_request(row)[0]


def _spa_form(controls, route: str, button: str = "Submit") -> str | None:
    form = {"controls": controls, "button": button, "button_aria": "", "action": None}
    return spa.form_refusal(form, route, named=None) or spa.captcha_reason(form)


@dataclass(frozen=True)
class Route:
    lab: str
    method: str
    url: str          # absolute URL as the app serves it
    effect: str       # what a request changes (from the app's source)
    gate: str         # visit | request | body | form | spa-form
    verdict: object   # () -> the gate's verdict (a reason, or None)
    expect: str       # "refused", or "residual: <why accepted>"


# --- Juice Shop (source: juice-catalogue-notes.md, server.ts routes) -----------------
# The SPA's own change-password form (change-password.component.html: three password
# controls on route /privacy-security/change-password) and contact form (a captcha
# control): the crawler refuses to submit either, so their XHRs are never captured.
_JUICE_CHANGE_PASSWORD_SPA = [("ng.form0.currentPassword", "password"),
                              ("ng.form0.newPassword", "password"),
                              ("ng.form0.newPasswordRepeat", "password")]
_JUICE_FEEDBACK_SPA = [("ng.form0.comment", "textarea"), ("ng.form0.rating", "range"),
                       ("ng.form0.captchaControl", "text")]
#: views/dataErasureForm.hbs, juice-shop master (captured third-party shape, PA-0111(3)).
JUICE_DATAERASURE_FORM = """<form action="/dataerasure" method="POST">
    <div class="form-field">
        <label for="email">Confirm Email Address</label>
        <input type="email" required placeholder=bender@juice-sh.op name="email" id="email">
    </div>
    <div class="form-field">
        <label for="securityAnswer">Answer</label>
        <input type="text" required placeholder="Your eldest siblings middle name?"
            id="securityAnswer" name="securityAnswer">
    </div>
    <div class="deleteButton">
    <button type="submit">
        <span class="cross">&times;</span>
    Delete User Data</button>
    </div>
</form>"""


def _req(method, path):
    return lambda: request_refusal(method, JUICE + path)


JUICE_ROUTES = [
    Route("juice", "POST", JUICE + "/rest/user/reset-password",
          "resets a user's password from a security answer (resetPassword.ts)",
          "request", _req("POST", "/rest/user/reset-password"), "refused"),
    Route("juice", "POST", JUICE + "/rest/2fa/setup", "enables 2FA on the account",
          "request", _req("POST", "/rest/2fa/setup"), "refused"),
    Route("juice", "POST", JUICE + "/rest/2fa/disable", "disables 2FA on the account",
          "request", _req("POST", "/rest/2fa/disable"), "refused"),
    Route("juice", "POST", JUICE + "/rest/basket/1/checkout",
          "places an order and empties the basket (placeOrder)",
          "request", _req("POST", "/rest/basket/1/checkout"), "refused"),
    Route("juice", "PUT", JUICE + "/rest/wallet/balance", "adds to the wallet balance",
          "request", _req("PUT", "/rest/wallet/balance"), "refused"),
    Route("juice", "POST", JUICE + "/rest/deluxe-membership",
          "upgrades the account to deluxe (spends wallet)",
          "request", _req("POST", "/rest/deluxe-membership"), "refused"),
    Route("juice", "POST", JUICE + "/b2b/v2/orders", "places a B2B order",
          "request", _req("POST", "/b2b/v2/orders"), "refused"),
    Route("juice", "PUT", JUICE + "/rest/order-history/1/delivery-status",
          "toggles an order's delivery status (accounting)",
          "request", _req("PUT", "/rest/order-history/1/delivery-status"), "refused"),
    Route("juice", "POST", JUICE + "/rest/web3/walletNFTVerify", "verifies an NFT wallet",
          "request", _req("POST", "/rest/web3/walletNFTVerify"), "refused"),
    Route("juice", "POST", JUICE + "/rest/web3/walletExploitAddress",
          "starts a contract-exploit listener", "request",
          _req("POST", "/rest/web3/walletExploitAddress"), "refused"),
    Route("juice", "DELETE", JUICE + "/api/Cards/1", "deletes a stored payment card",
          "request", _req("DELETE", "/api/Cards/1"), "refused"),
    Route("juice", "DELETE", JUICE + "/api/Addresss/1", "deletes a stored address",
          "request", _req("DELETE", "/api/Addresss/1"), "refused"),
    Route("juice", "PUT", JUICE + "/api/BasketItems/1", "rewrites a basket item's quantity",
          "request", _req("PUT", "/api/BasketItems/1"), "refused"),
    Route("juice", "PUT", JUICE + "/api/Addresss/1", "rewrites a stored address",
          "request", _req("PUT", "/api/Addresss/1"), "refused"),
    Route("juice", "PUT", JUICE + "/rest/products/1/reviews", "creates a product review",
          "request", _req("PUT", "/rest/products/1/reviews"), "refused"),
    Route("juice", "PATCH", JUICE + "/rest/products/reviews", "rewrites a review's text",
          "request", _req("PATCH", "/rest/products/reviews"), "refused"),
    Route("juice", "PUT", JUICE + "/rest/basket/1/coupon/X", "applies a coupon",
          "request", _req("PUT", "/rest/basket/1/coupon/X"), "refused"),
    Route("juice", "PUT", JUICE + "/rest/continue-code/apply/X",
          "restores challenge progress from a code",
          "request", _req("PUT", "/rest/continue-code/apply/X"), "refused"),
    Route("juice", "GET", JUICE + "/rest/order-history", "reads orders (T-flagged)",
          "request", _req("GET", "/rest/order-history"), "refused"),
    Route("juice", "POST", JUICE + "/api/Users",
          "registers an account (email, password, passwordRepeat)",
          "body", lambda: _captured("POST", JUICE + "/api/Users", "application/json",
                                    {"email": "a@example.invalid", "password": "x",
                                     "passwordRepeat": "x", "securityAnswer": "y"},
                                    JUICE + "/"), "refused"),
    Route("juice", "POST", JUICE + "/file-upload", "stores an uploaded complaint file",
          "body", lambda: _captured("POST", JUICE + "/file-upload",
                                    "multipart/form-data; boundary=x", None, JUICE + "/"),
          "refused"),
    Route("juice", "POST", JUICE + "/profile/image/file", "replaces the profile image",
          "body", lambda: _captured("POST", JUICE + "/profile/image/file",
                                    "multipart/form-data; boundary=x", None, JUICE + "/"),
          "refused"),
    Route("juice", "POST", JUICE + "/rest/memories", "stores a photo memory on disk",
          "body", lambda: _captured("POST", JUICE + "/rest/memories",
                                    "multipart/form-data; boundary=x", None, JUICE + "/"),
          "refused"),
    Route("juice", "POST", JUICE + "/api/Feedbacks",
          "creates a feedback row (CAPTCHA-gated)", "spa-form",
          lambda: _spa_form(_JUICE_FEEDBACK_SPA, "contact"), "refused"),
    Route("juice", "GET", JUICE + "/rest/user/change-password?current=a&new=b&repeat=b",
          "changes the bearer's password (changePassword.ts; current optional)",
          "spa-form", lambda: _spa_form(_JUICE_CHANGE_PASSWORD_SPA,
                                        "privacy-security/change-password", "Change"),
          "refused"),
    # residuals: no gate refuses them; each is accepted for the reason given
    Route("juice", "POST", JUICE + "/api/Cards", "adds a payment card to the session user",
          "request", _req("POST", "/api/Cards"),
          "residual: row creation on the session user's own account (low)"),
    Route("juice", "POST", JUICE + "/api/BasketItems", "adds an item to the user's basket",
          "request", _req("POST", "/api/BasketItems"),
          "residual: row creation on the session user's own basket (low)"),
    Route("juice", "POST", JUICE + "/rest/products/reviews", "likes a review once per user",
          "request", _req("POST", "/rest/products/reviews"),
          "residual: a per-user like (low)"),
    Route("juice", "POST", JUICE + "/api/Recycles", "creates a recycle request",
          "request", _req("POST", "/api/Recycles"), "residual: row creation (low)"),
    Route("juice", "POST", JUICE + "/api/PrivacyRequests", "creates a privacy request",
          "request", _req("POST", "/api/PrivacyRequests"), "residual: row creation (low)"),
    Route("juice", "POST", JUICE + "/api/Addresss", "creates a stored address",
          "request", _req("POST", "/api/Addresss"), "residual: row creation (low)"),
    Route("juice", "POST", JUICE + "/api/Complaints", "creates a complaint",
          "request", _req("POST", "/api/Complaints"), "residual: row creation (low)"),
    Route("juice", "GET", JUICE + "/rest/saveLoginIp",
          "rewrites the session user's lastLoginIp", "request",
          _req("GET", "/rest/saveLoginIp"),
          "residual: the session user's own row; the page is the header-XSS sink"),
    Route("juice", "POST", JUICE + "/profile", "rewrites the session user's username",
          "request", _req("POST", "/profile"),
          "residual: a ground-truth cell (JUICE-0006/0008): fuzzing it is the purpose"),
    Route("juice", "POST", JUICE + "/profile/image/url",
          "fetches a URL and stores it as the profile image", "request",
          _req("POST", "/profile/image/url"),
          "residual: a ground-truth cell (JUICE-0005/0012); its egress is the SSRF row"),
    Route("juice", "GET", JUICE + "/rest/web3/nftMintListen",
          "opens an outbound WSS listener (no lab state)", "request",
          _req("GET", "/rest/web3/nftMintListen"),
          "residual: egress, not lab state (the fixture's network placement)"),
]


# --- BUG-0301: the two Juice Shop routes the rule misses (strict, PA-0054(3)) --------
_BUG_0301 = "BUG-0301 (CC-CORE-0301): deferred to the owner of fuzzlab/core/urls.py"
JUICE_CHANGE_PASSWORD = JUICE + "/rest/user/change-password?current=a&new=b&repeat=b"
JUICE_DATAERASURE = JUICE + "/dataerasure"


@pytest.mark.xfail(strict=True, reason=_BUG_0301)
def test_juice_change_password_url_is_refused():
    assert destructive_reason(JUICE_CHANGE_PASSWORD) is not None


@pytest.mark.xfail(strict=True, reason=_BUG_0301)
def test_juice_change_password_url_is_refused_at_the_send_gate():
    with pytest.raises(DestructiveUrlRefused):
        check_send_url(JUICE_CHANGE_PASSWORD, method="GET")


@pytest.mark.xfail(strict=True, reason=_BUG_0301)
def test_juice_dataerasure_url_is_refused():
    assert destructive_reason(JUICE_DATAERASURE) is not None


@pytest.mark.xfail(strict=True, reason=_BUG_0301)
def test_juice_dataerasure_form_is_never_imported():
    assert form_skip_reason(_form(JUICE_DATAERASURE_FORM, JUICE_DATAERASURE)) is not None


def test_bug_0301_is_what_the_xfails_claim():
    """The strict xfails above fail for the stated reason, not another: today the URL
    rule, the send gate and the form gate all let both routes through."""
    for url in (JUICE_CHANGE_PASSWORD, JUICE_DATAERASURE):
        assert destructive_reason(url) is None and transaction_reason(url) is None
        check_send_url(url, method="GET")                  # no refusal
    assert form_skip_reason(_form(JUICE_DATAERASURE_FORM, JUICE_DATAERASURE)) is None


def test_bug_0301_compensating_controls_hold_meanwhile():
    """What stops the two routes today (stated in BUG-0301): the crawler never submits
    the SPA's change-password form (so its XHR is never captured), a captured GET XHR
    has no body to import, and a captured form-encoded erasure POST is refused for its
    security-answer field. The server-rendered erasure form is the uncovered path."""
    assert _spa_form(_JUICE_CHANGE_PASSWORD_SPA, "privacy-security/change-password",
                     "Change") is not None
    assert _captured("GET", JUICE_CHANGE_PASSWORD, None, None, JUICE + "/") is not None
    assert _captured("POST", JUICE_DATAERASURE, "application/x-www-form-urlencoded",
                     {"email": "a@example.invalid", "securityAnswer": "x"},
                     JUICE_DATAERASURE) is not None


# --- bWAPP (source: bwapp-catalogue-notes.md "Destructive", bWAPP v2.2 source) -------
def _bw(page: str) -> str:
    return f"{BWAPP}/bWAPP/{page}"


def _bw_form(markup: str, page: str):
    return lambda: form_skip_reason(_form(markup, _bw(page)))


#: The real forms, PHP stripped (`<?php ... ?>` -> ""): page:line of each <form>.
BW_PASSWORD_CHANGE = """<form action="" method="POST">
  <input type="password" id="password_curr" name="password_curr">
  <input type="password" id="password_new" name="password_new">
  <input type="password" id="password_conf" name="password_conf">
  <button type="submit" name="action" value="change">Change</button></form>"""  # :180
BW_CSRF_1 = BW_PASSWORD_CHANGE.replace('method="POST"', 'method="GET"')       # :211
BW_VERB_TAMPERING = """<form action="" method="POST">
  <input type="password" id="password_new" name="password_new">
  <input type="password" id="password_conf" name="password_conf">
  <button type="submit" name="action" value="change">Change</button></form>"""  # :245
BW_SECRET_CHANGE = """<form action="" method="POST">
  <input type="text" id="secret" name="secret">
  <input type="hidden" id="email" name="email" value="" />
  <input type="hidden" id="reset_code" name="reset_code" value="" />
  <button type="submit" name="action" value="change">Change</button></form>"""  # :154
BW_SECRET_OWN = """<form action="" method="POST">
  <input type="text" id="secret" name="secret">
  <input type="hidden" name="login" value="bee">
  <input type="hidden" id="token" name="token" value="t">
  <button type="submit" name="action" value="change">Change</button></form>"""
BW_USER_NEW = """<form action="" method="POST">
  <input type="text" id="login" name="login"><input type="text" id="email" name="email">
  <input type="password" id="password" name="password">
  <input type="password" id="password_conf" name="password_conf">
  <input type="text" id="secret" name="secret">
  <input type="checkbox" id="mail_activation" name="mail_activation" value="">
  <button type="submit" name="action" value="create">Create</button></form>"""  # :303
BW_LDAP = """<form action="" method="POST">
  <input type="text" id="login" name="login"><input type="password" id="password" name="password">
  <input type="text" id="server" name="server"><input type="text" id="dn" name="dn">
  <button type="submit" name="set" value="submit">Set</button></form>"""        # :313
BW_LEVEL = """<form action="" method="POST">
  <select name="security_level"><option value="0">low</option><option value="1">medium</option>
  <option value="2">high</option></select>
  <button type="submit" name="form_security_level" value="submit">Set</button></form>"""
BW_LEVEL_SET = BW_LEVEL.replace('name="form_security_level"', 'name="form"')   # :130
BW_SQLI_12 = """<form action="" method="POST">
  <textarea name="entry" id="entry" cols="80" rows="3"></textarea>
  <button type="submit" name="entry_add" value="add">Add Entry</button>
  <button type="submit" name="entry_delete" value="delete">Delete Entries</button></form>"""
BW_BLOG = """<form action="" method="POST">
  <textarea name="entry" id="entry" cols="80" rows="3"></textarea>
  <button type="submit" name="blog" value="submit">Submit</button>
  <input type="checkbox" id="entry_add" name="entry_add" value="" checked="on">
  <input type="checkbox" id="entry_all" name="entry_all" value="">
  <input type="checkbox" id="entry_delete" name="entry_delete" value=""></form>"""
# (BW_BLOG: xss_stored_1.php:206 and htmli_stored.php, the same blog form)
BW_SSII = """<form action="" method="POST">
  <input type="text" id="firstname" name="firstname">
  <input type="text" id="lastname" name="lastname">
  <button type="submit" name="form" value="submit">Lookup</button></form>"""    # :146
BW_UPLOAD = """<form action="" method="POST" enctype="multipart/form-data">
  <input type="file" name="file"><input type="hidden" name="MAX_FILE_SIZE" value="10">
  <input type="submit" name="form" value="Upload"></form>"""
BW_CRYPT_2 = """<form action="" method="POST">
  <input type="text" id="username" name="username">
  <input type="password" id="password" name="password">
  <button type="submit" name="insert" value="Insert">Insert</button></form>"""


def _sent_names(markup: str, page: str) -> set[str]:
    return {n for n, _v in _form(markup, _bw(page))["entries"]}


BWAPP_ROUTES = [
    Route("bwapp", "GET", _bw("reset.php"), "DROP DATABASE and re-seed", "visit",
          lambda: destructive_reason(_bw("reset.php")), "refused"),
    Route("bwapp", "GET", _bw("update.php"), "rebuilds the database (unauthenticated)",
          "visit", lambda: destructive_reason(_bw("update.php")), "refused"),
    Route("bwapp", "GET", _bw("install.php?install=yes"), "creates the database",
          "visit", lambda: destructive_reason(_bw("install.php?install=yes")), "refused"),
    Route("bwapp", "GET", _bw("logout.php"), "ends the session", "visit",
          lambda: destructive_reason(_bw("logout.php")), "refused"),
    Route("bwapp", "GET", _bw("ba_logout.php"), "ends the session", "visit",
          lambda: destructive_reason(_bw("ba_logout.php")), "refused"),
    Route("bwapp", "GET", _bw("ba_logout_1.php"), "session_destroy() on a visit", "visit",
          lambda: destructive_reason(_bw("ba_logout_1.php")), "refused"),
    Route("bwapp", "GET", _bw("ldap_connect.php?clear="), "clears the LDAP settings",
          "visit", lambda: destructive_reason(_bw("ldap_connect.php?clear=")), "refused"),
    Route("bwapp", "GET", _bw("insecure_crypt_storage_2.php?delete="),
          "deletes the stored credentials file", "visit",
          lambda: destructive_reason(_bw("insecure_crypt_storage_2.php?delete=")), "refused"),
    Route("bwapp", "POST", _bw("insecure_crypt_storage_2.php"), "appends to a password file",
          "form", _bw_form(BW_CRYPT_2, "insecure_crypt_storage_2.php"), "refused"),
    Route("bwapp", "POST", _bw("password_change.php"), "UPDATE users SET password",
          "form", _bw_form(BW_PASSWORD_CHANGE, "password_change.php"), "refused"),
    Route("bwapp", "GET", _bw("csrf_1.php"), "UPDATE users SET password on a GET",
          "form", _bw_form(BW_CSRF_1, "csrf_1.php"), "refused"),
    Route("bwapp", "POST", _bw("http_verb_tampering.php"), "UPDATE users SET password",
          "form", _bw_form(BW_VERB_TAMPERING, "http_verb_tampering.php"), "refused"),
    Route("bwapp", "POST", _bw("secret_change.php"), "UPDATE users SET secret by e-mail",
          "form", _bw_form(BW_SECRET_CHANGE, "secret_change.php"), "refused"),
    Route("bwapp", "POST", _bw("user_new.php"), "INSERT INTO users", "form",
          _bw_form(BW_USER_NEW, "user_new.php"), "refused"),
    Route("bwapp", "POST", _bw("ldap_connect.php"), "stores LDAP connection settings",
          "form", _bw_form(BW_LDAP, "ldap_connect.php"), "refused"),
    Route("bwapp", "POST", _bw("security_level_set.php"),
          "sets the security_level cookie (invalidates the ground truth)", "form",
          _bw_form(BW_LEVEL_SET, "security_level_set.php"), "refused"),
    Route("bwapp", "POST", _bw("portal.php"),
          "the sidebar form on every page (selections.php): sets security_level",
          "form", _bw_form(BW_LEVEL, "portal.php"), "refused"),
    Route("bwapp", "POST", _bw("unrestricted_file_upload.php"), "writes an uploaded file",
          "form", _bw_form(BW_UPLOAD, "unrestricted_file_upload.php"), "refused"),
    Route("bwapp", "POST", _bw("backdoor.php"),
          "writes an uploaded file to any directory (unauthenticated)", "form",
          _bw_form(BW_UPLOAD.replace('name="form"', 'name="upload"'), "backdoor.php"),
          "refused"),
    Route("bwapp", "POST", _bw("xxe-2.php"), "UPDATE users SET secret from an XML body",
          "body", lambda: _captured("POST", _bw("xxe-2.php"), "text/xml; charset=UTF-8",
                                    None, _bw("xxe-1.php")), "refused"),
    Route("bwapp", "POST", _bw("sqli_8-2.php"), "UPDATE users SET secret from an XML body",
          "body", lambda: _captured("POST", _bw("sqli_8-2.php"), "text/xml; charset=UTF-8",
                                    None, _bw("sqli_8-1.php")), "refused"),
    # residuals
    Route("bwapp", "GET", _bw("restrict_folder_access.php"),
          "deletes documents/.htaccess on a visit", "visit",
          lambda: destructive_reason(_bw("restrict_folder_access.php")),
          "residual: the page's own demo; stated in FR-CRAWL-8 (BUG-0114)"),
    Route("bwapp", "GET", _bw("sm_cross_domain_policy.php"),
          "rewrites ../crossdomain.xml on a visit", "visit",
          lambda: destructive_reason(_bw("sm_cross_domain_policy.php")),
          "residual: an idempotent rewrite of a fixed file per security level"),
    Route("bwapp", "GET", _bw("sqli_9.php?action=stop"),
          "sets a session flag (manual_interv) only", "visit",
          lambda: destructive_reason(_bw("sqli_9.php?action=stop")),
          "residual: session-scoped flag, no lab state"),
    Route("bwapp", "POST", _bw("xss_stored_3.php"),
          "UPDATE users SET secret for the hidden login", "form",
          _bw_form(BW_SECRET_OWN, "xss_stored_3.php"),
          "residual: the hidden login is an object selector (never fuzzed, sent as "
          "rendered), so only the session user's own secret changes; the page is a "
          "stored-XSS source"),
    Route("bwapp", "POST", _bw("csrf_3.php"), "UPDATE users SET secret for the hidden login",
          "form", _bw_form(BW_SECRET_OWN, "csrf_3.php"),
          "residual: as xss_stored_3 (own secret only)"),
    Route("bwapp", "POST", _bw("insecure_direct_object_ref_1.php"),
          "UPDATE users SET secret for the hidden login", "form",
          _bw_form(BW_SECRET_OWN, "insecure_direct_object_ref_1.php"),
          "residual: as xss_stored_3 (own secret only)"),
    Route("bwapp", "POST", _bw("sqli_12.php"), "adds a blog entry (delete is a 2nd button)",
          "form", _bw_form(BW_SQLI_12, "sqli_12.php"),
          "residual: row creation; the delete button is not the default submitter and "
          "is never sent"),
    Route("bwapp", "POST", _bw("xss_stored_1.php"),
          "adds a blog entry (delete is an unchecked checkbox)", "form",
          _bw_form(BW_BLOG, "xss_stored_1.php"),
          "residual: row creation; the unchecked entry_delete box is never sent"),
    Route("bwapp", "POST", _bw("htmli_stored.php"), "adds a blog entry", "form",
          _bw_form(BW_BLOG, "htmli_stored.php"), "residual: as xss_stored_1"),
    Route("bwapp", "POST", _bw("ssii.php"), "rewrites ssii.shtml at the app root", "form",
          _bw_form(BW_SSII, "ssii.php"),
          "residual: the page's own per-request file rewrite"),
    Route("bwapp", "GET", _bw("sqli_17.php"), "INSERT INTO visitors per request", "visit",
          lambda: destructive_reason(_bw("sqli_17.php")),
          "residual: row creation per request; a ground-truth cell"),
    Route("bwapp", "GET", _bw("xss_stored_4.php"), "INSERT INTO visitors per request",
          "visit", lambda: destructive_reason(_bw("xss_stored_4.php")),
          "residual: row creation per request; a ground-truth cell"),
    Route("bwapp", "POST", _bw("commandi.php"), "runs nslookup on the input (RCE demo)",
          "visit", lambda: destructive_reason(_bw("commandi.php")),
          "residual: the route is the vulnerability; damage is bounded by the payloads "
          "and the fixture container, not by a URL rule"),
    Route("bwapp", "POST", _bw("commandi_blind.php"), "pings the input (RCE demo)",
          "visit", lambda: destructive_reason(_bw("commandi_blind.php")),
          "residual: as commandi"),
    Route("bwapp", "GET", _bw("php_eval.php"), "eval()s the input (RCE demo)", "visit",
          lambda: destructive_reason(_bw("php_eval.php")), "residual: as commandi"),
    Route("bwapp", "GET", _bw("phpi.php"), "eval()s the message (RCE demo)", "visit",
          lambda: destructive_reason(_bw("phpi.php")), "residual: as commandi"),
    Route("bwapp", "GET", _bw("rlfi.php"), "includes the language file (RFI demo)",
          "visit", lambda: destructive_reason(_bw("rlfi.php")), "residual: as commandi"),
    Route("bwapp", "POST", _bw("ba_forgotten.php"), "sends mail() (egress)", "visit",
          lambda: destructive_reason(_bw("ba_forgotten.php")),
          "residual: egress, not lab state (the fixture's network placement)"),
]


ALL_ROUTES = JUICE_ROUTES + BWAPP_ROUTES


@pytest.mark.parametrize("route", ALL_ROUTES, ids=lambda r: f"{r.lab}:{r.method}:{r.url}")
def test_each_destructive_route_gets_its_gates_actual_verdict(route):
    verdict = route.verdict()
    if route.expect == "refused":
        assert verdict is not None, f"{route.url}: {route.gate} gate let it through"
    else:
        assert route.expect.startswith("residual: ") and len(route.expect) > 20
        assert verdict is None, (f"{route.url} is now refused ({verdict!r}): move it "
                                 "from the residuals to 'refused'")


def test_the_bwapp_residuals_hold_for_the_reason_stated():
    """The non-URL compensating controls the residual rows cite, computed."""
    assert _object_selector("login")                        # the hidden login: never fuzzed
    assert "entry_delete" not in _sent_names(BW_SQLI_12, "sqli_12.php")
    assert "entry_delete" not in _sent_names(BW_BLOG, "xss_stored_1.php")
    assert "entry_add" in _sent_names(BW_SQLI_12, "sqli_12.php")


def test_the_juice_method_gates_hold_at_the_send_too():
    """A DELETE is refused again at the send unless enumerated (FR-FUZZ-47)."""
    for path in ("/api/Cards/1", "/api/Addresss/1"):
        with pytest.raises(DestructiveUrlRefused):
            check_send_url(JUICE + path, method="DELETE")


def test_the_bwapp_table_covers_the_existing_pa_0114_list():
    """`test_forms_phase1.BWAPP_DESTRUCTIVE_GETS` (BUG-0114) is a subset of this table
    (A18): the catalogue's list was compared with it and extended, never narrowed."""
    from tests.test_forms_phase1 import BWAPP_DESTRUCTIVE_GETS, BWAPP_NOT_URL_CAUGHT
    paths = {r.url.split(BWAPP, 1)[1].split("?", 1)[0] for r in BWAPP_ROUTES}
    for p in [*BWAPP_DESTRUCTIVE_GETS, *BWAPP_NOT_URL_CAUGHT]:
        assert p.split("?", 1)[0] in paths, p


# --- PA-0002 sweep: the generated labs' state-changing routes -------------------------
def _generated_lab_routes() -> list[tuple[str, str, str]]:
    """Every non-GET route the generated labs serve as a cell (lab/manifests/*.yaml)
    or score (lab/ground-truth*/), as ``(source, method, path)``."""
    out = set()
    for path in sorted(glob.glob(str(ROOT / "lab/manifests/*.yaml"))):
        for cell in (yaml.safe_load(Path(path).read_text()) or {}).get("cells") or []:
            route = cell.get("route") or {}
            if (route.get("method") or "GET").upper() != "GET":
                out.add((Path(path).name, route["method"].upper(), route["path"]))
    for gt in sorted(glob.glob(str(ROOT / "lab/ground-truth*/"))):
        for name, key in (("injection-points.json", "points"), ("labels.json", "cases")):
            f = Path(gt) / name
            if not f.exists():
                continue
            data = json.loads(f.read_text())
            items = data.get(key, []) if isinstance(data, dict) else data
            for it in items:
                if isinstance(it, dict) and (it.get("method") or "GET").upper() != "GET":
                    out.add((Path(gt).name, it["method"].upper(), it["url"]))
    return sorted(out)


def test_the_generated_labs_state_changing_routes_are_enumerated_and_judged():
    """PA-0002 for BUG-0301 over the generated labs: every non-GET route is either
    refused by the rule or a scored cell -- a ground-truth run sends it as an explicit
    point, and a crawl run fuzzing it exercises the cell's own sink, which is the lab's
    purpose (the lab is disposable: `labctl.sh reset`). No generated lab serves a
    logout, delete or reset route at all."""
    routes = _generated_lab_routes()
    assert len(routes) >= 30                       # the enumeration found the labs
    for _src, method, path in routes:
        assert method in ("POST", "PUT", "PATCH")
        verdict = request_refusal(method, "http://127.0.0.1:8080" + path,
                                  fuzz_json_writes=True)
        assert verdict is None or "transaction" in verdict, (path, verdict)


# --- PA-0301: compound and verb-object spellings, over every lab's routes -------------
#: A destructive or transaction word this short is too common inside other words to
#: scan for as a substring (``del`` in ``model``, ``pay`` in ``display``).
MIN_STEM = 5
#: Words the rule does not have yet but a compound spelling has shown to need
#: (BUG-0301: ``erasure``); scanned as stems only.
EXTRA_STEMS = frozenset({"erasure", "logout", "signout"})
#: A credential-change verb-object pair, in either order (``change-password``,
#: ``password_change``).
CHANGE_VERBS = frozenset({"change", "update", "reset", "set", "edit", "modify"})
CREDENTIAL_OBJECTS = frozenset({"password", "passwd", "pwd", "email", "secret", "pin"})


def spelling_hits(url: str) -> list[str]:
    """Destructive/transaction words hidden inside a longer token, and credential
    verb-object pairs, in ``url``'s path and query (tokenised as the rule does)."""
    tokens = _url_tokens(url)
    stems = {s for s in DESTRUCTIVE_TOKENS | TRANSACTION_TOKENS | EXTRA_STEMS
             if len(s) >= MIN_STEM}
    hits = sorted({f"{s} in {t}" for t in tokens for s in stems if s in t and s != t})
    for a, b in zip(tokens, tokens[1:]):
        if {a, b} & CHANGE_VERBS and {a, b} & CREDENTIAL_OBJECTS:
            hits.append(f"{a} {b}")
    return hits


#: Each route the scan flags and the rule does not refuse: its disposition.
SPELLING_DISPOSITIONS = {
    JUICE + "/rest/user/change-password": "BUG-0301 (strict xfail above)",
    JUICE + "/dataerasure": "BUG-0301 (strict xfail above)",
    _bw("password_change.php"): "a GET visit only renders the form; the change needs its "
                                "three password controls, which credential_change_rule "
                                "refuses (row above)",
    _bw("secret_change.php"): "the form is refused for its reset_code entry (row above)",
    "/channels/subscribers": "a plural noun of a read-only listing (GET), not an action",
}


def _every_lab_route() -> list[str]:
    urls = {r.url.split("?", 1)[0] for r in ALL_ROUTES}
    urls |= {JUICE_CHANGE_PASSWORD.split("?", 1)[0], JUICE_DATAERASURE}
    urls |= {path for _s, _m, path in _generated_lab_routes()}
    for path in sorted(glob.glob(str(ROOT / "lab/manifests/*.yaml"))):
        for cell in (yaml.safe_load(Path(path).read_text()) or {}).get("cells") or []:
            urls.add((cell.get("route") or {}).get("path") or "/")
    return sorted(urls)


def _the_rule(url: str) -> str | None:
    return destructive_reason(url) or transaction_reason(url)


def unlisted_spelling_misses(urls, dispositions, rule=_the_rule) -> list[str]:
    """Routes the scan flags, the ``rule`` does not refuse, and no disposition covers."""
    return [url for url in urls
            if spelling_hits(url) and rule(url) is None and url not in dispositions]


def test_no_lab_route_hides_a_destructive_word_in_a_compound():
    urls = _every_lab_route()
    assert unlisted_spelling_misses(urls, SPELLING_DISPOSITIONS) == []
    stale = [u for u in SPELLING_DISPOSITIONS
             if u not in urls or not spelling_hits(u) or destructive_reason(u)
             or transaction_reason(u)]
    assert stale == [], "a disposition is stale: the rule now refuses it, or no route has it"


def test_the_spelling_scan_catches_synthetic_offenders():
    """PA-0034(2): shapes built to be missed by a whole-token rule (an object-verb
    compound, a camelCase or snake_case credential pair) are caught by the scan, and an
    unlisted one fails the sweep against a rule that misses it; a route the real rule
    refuses is never a miss. A substring scan also hits harmless nouns (``clearance``):
    such a hit needs a written disposition, never a silent pass (PA-0022's vocabulary
    check, made a test)."""
    def misses_everything(_url):
        return None
    for bad in ("/account/accountdelete", "/user/dataerasure", "/api/changePassword",
                "/x/update_email", "/privacy/userlogout"):
        assert spelling_hits(bad), bad
        assert unlisted_spelling_misses([bad], {}, rule=misses_everything) == [bad], bad
        assert unlisted_spelling_misses([bad], {bad: "listed"},
                                        rule=misses_everything) == [], bad
    assert spelling_hits("/x/password-reset") == ["password reset"]
    assert unlisted_spelling_misses(["/x/password-reset"], {}) == []   # 'reset' refused
    for ok in ("/model?id=1", "/display.php", "/sqli_1.php", "/delivery.php",
               "/portal.php"):
        assert spelling_hits(ok) == [], ok
    assert spelling_hits("/clearance.php") == ["clear in clearance"]
