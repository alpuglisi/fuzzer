"""The crAPI fixture's bootstrap and account values, with a fake of crAPI's API
(FR-LAB-436, CC-LAB-0436): sign-up when the login fails, a verified login (dashboard
names the account, a wrong password gets no token), the vehicle from the welcome mail, a mechanic
report, an order and a claimed coupon; the stored values are the account's own ids."""

from __future__ import annotations

import quopri
from types import SimpleNamespace as NS

import pytest

from fuzzlab.lab_fixtures import external as ext


class _Resp:
    def __init__(self, status, body=None, text=""):
        self.status_code, self._body, self.text = status, body, text or ""
        self.headers = {}

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body

    def close(self):
        pass


def _welcome(vin: str, pin: str) -> str:
    html = (f"<p><font>Your vehicle information is <b>VIN: </font><font color='#0000ff'>"
            f"{vin}</font></b> and <b>Pincode: <font color='#0000ff'>{pin}</font></b></p>")
    return quopri.encodestring(html.encode()).decode()


class FakeCrapi:
    """Routes by (method, path); tokens are ``tok-<email>``."""

    def __init__(self, *, mail=True, coupon_claimed=False):
        self.users: dict[str, str] = {}
        self.vehicles: dict[str, dict] = {}
        self.reports: dict[str, list] = {}
        self.orders: dict[str, list] = {}
        self.claimed = {"fuzzlab-user@example.com"} if coupon_claimed else set()
        self.mail = mail
        self.mails: list[tuple[str, str]] = []
        self.calls: list[tuple[str, str]] = []
        self.origin = "http://127.0.0.1:3101"

    def url(self, path):
        return self.origin + path

    def _who(self, headers):
        auth = (headers or {}).get("Authorization", "")
        email = auth.removeprefix("Bearer tok-")
        return email if auth.startswith("Bearer tok-") and email in self.users else None

    def request(self, method, path, *, anonymous=False, json=None, params=None,
                headers=None, **kw):
        self.calls.append((method, path))
        who = self._who(headers)
        if path == "/health":
            return _Resp(200, text="OK")
        if (method, path) == ("POST", "/identity/api/auth/login"):
            ok = self.users.get(json["email"]) == json["password"]
            return _Resp(200, {"token": f"tok-{json['email']}"}) if ok else \
                _Resp(401, {"token": None, "message": "Invalid Credentials"})
        if (method, path) == ("POST", "/identity/api/auth/signup"):
            assert len(json["number"]) == 10 and json["name"] and json["password"]
            self.users[json["email"]] = json["password"]
            if self.mail:
                self.mails.append((json["email"], _welcome("7ECOX34KJTV359804", "4321")))
            return _Resp(200, {"message": "User registered successfully! Please Login."})
        if path == "/identity/api/v2/user/dashboard":
            return _Resp(200, {"email": who}) if who else _Resp(404, {})
        if path.startswith("/mailhog/api/v2/search?"):
            from urllib.parse import parse_qs, urlsplit
            query = parse_qs(urlsplit(path).query)
            assert query["kind"] == ["to"]
            items = [{"Created": "2026-11-20T13:39:28Z", "Raw": {"Data": body}}
                     for to, body in self.mails if to == query["query"][0]]
            return _Resp(200, {"items": items})
        assert who, (method, path)
        if path == "/identity/api/v2/vehicle/vehicles":
            v = self.vehicles.get(who)
            return _Resp(200, [v] if v else [])
        if path == "/identity/api/v2/vehicle/add_vehicle":
            assert (json["vin"], json["pincode"]) == ("7ECOX34KJTV359804", "4321")
            self.vehicles[who] = {"uuid": f"uuid-{who}", "vin": json["vin"]}
            return _Resp(200, {"message": "Vehicle save successfully.."})
        if path.startswith("/workshop/api/merchant/service_requests/"):
            return _Resp(200, {"service_requests": self.reports.get(who, [])})
        if path == "/workshop/api/merchant/contact_mechanic":
            assert json["mechanic_api"] == self.origin + \
                "/workshop/api/mechanic/receive_report"
            self.reports[who] = [{"id": 6 + len(self.reports)}]
            return _Resp(200, {"response_from_mechanic_api": {"sent": True}})
        if path == "/workshop/api/shop/orders/all":
            return _Resp(200, {"orders": self.orders.get(who, [])})
        if path == "/workshop/api/shop/products":
            return _Resp(200, {"products": [{"id": 2}, {"id": 1}]})
        if (method, path) == ("POST", "/workshop/api/shop/orders"):
            self.orders[who] = [{"id": 40 + len(self.orders)}]
            return _Resp(200, {"id": 40})
        if path == "/workshop/api/shop/apply_coupon":
            if who in self.claimed:
                return _Resp(400, text='{"message":"TRAC075 Coupon code is already claimed '
                                       'by you!! Please try with another coupon code"}')
            self.claimed.add(who)
            return _Resp(200, {"credit": 175.0})
        raise AssertionError((method, path))


def _cred(email="fuzzlab-user@example.com", pw="pw-123456"):
    return NS(username=email, password=pw)


def test_the_crapi_bootstrap_signs_up_verifies_and_gives_the_account_its_objects():
    lab = FakeCrapi()
    notes = ext.bootstrap_crapi(lab, _cred(), deadline=1, sleep=lambda s: None)
    assert notes == ["account signed up", "login verified", "vehicle added",
                     "mechanic report created", "order placed", "coupon claimed"]
    assert ext.crapi_account_attributes(lab, _cred()) == {
        "vehicle_id": "uuid-fuzzlab-user@example.com", "vin": "7ECOX34KJTV359804",
        "report_id": "6", "order_id": "40"}
    # idempotent: a second run logs in and adds nothing
    lab.calls.clear()
    assert ext.bootstrap_crapi(lab, _cred(), deadline=1, sleep=lambda s: None) == \
        ["login verified"]
    assert ("POST", "/identity/api/auth/signup") not in lab.calls


def test_the_crapi_bootstrap_refuses_an_unverified_login_and_a_missing_mail():
    lab = FakeCrapi()
    lab.users["fuzzlab-user@example.com"] = "another-password"
    with pytest.raises(ext.ExternalLabError, match="signup failed|login of"):
        lab.request = (lambda orig: lambda m, p, **kw: _Resp(403, {}) if
                       p.endswith("/signup") else orig(m, p, **kw))(lab.request)
        ext.bootstrap_crapi(lab, _cred(), deadline=1, sleep=lambda s: None)
    quiet = FakeCrapi(mail=False)
    clock = iter(range(100))
    with pytest.raises(ext.ExternalLabError, match="no crAPI vehicle mail"):
        ext.bootstrap_crapi(quiet, _cred(), deadline=3, sleep=lambda s: None,
                            clock=lambda: next(clock))


def test_the_crapi_meta_has_two_accounts_of_our_own_on_a_free_loopback_port():
    meta = ext.LAB_META["crapi"]
    assert [a.identity for a in meta.accounts()] == ["crapi-user", "crapi-peer"]
    assert meta.may_generate_password and meta.default_port == 3101
    assert ext.CRAPI_WEB_IMAGE in ext.PINNED_IMAGES and ext.CRAPI_POSTGRES_IMAGE in \
        ext.PINNED_IMAGES
    assert ext._crapi_number("a@example.com") == ext._crapi_number("a@example.com")
    assert ext._crapi_number("a@example.com") != ext._crapi_number("b@example.com")
