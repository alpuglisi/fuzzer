"""Real, executed live-boot proof for Netflix's fifth real page
(`CC-LAB-0188`, `FR-LAB-143`): this stack's first `price_integrity_bypass`
instance, a subscription plan-upgrade/downgrade endpoint at
`POST /api/subscription/change-plan`.

Mirrors `tests/test_labgen_spring_boot_account_billing_live_boot.py`'s own
shape (each-twin-its-own-boot, real HTTP requests against a real booted
Spring Boot app). This concern (`price_integrity_bypass`) has no audit-rule/
oracle-strategy detection anywhere in the project yet (deliberately, this
task's own lab/detection split), so unlike the account-billing live-boot
test there is no third "detection generalizes for free" test here -- that
is deferred to a separate follow-on entry per this task's own explicit
instruction, tracked in `docs/components/01-target-lab/change-control.md`.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked `@pytest.
mark.slow`.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

_MANIFEST_PATH = "lab/manifests/price_integrity_netflix_subscription_sample.yaml"
_ROUTE = "/api/subscription/change-plan"

pytestmark = [
    pytest.mark.skipif(
        not spring_boot_boot_available(),
        reason=(
            "live-boot harness requires java + mvn on PATH and real Maven Central "
            "network reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
        ),
    ),
    pytest.mark.slow,
]


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def _post_json(harness: SpringBootLiveBootHarness, body: dict) -> "object":
    return harness.request(
        "POST", _ROUTE, data=json.dumps(body).encode("utf-8"), content_type="application/json"
    )


def test_vulnerable_twin_trusts_and_reflects_the_manipulated_client_price() -> None:
    """The differential the task asks for: a Standard-tier change request
    with an attacker-supplied `monthly_charge: 0.01` results in that
    trusted, wrong amount being reflected back verbatim -- never the real
    Standard price ($15.49)."""
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0009"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = _post_json(harness, {"plan_tier": "standard", "monthly_charge": 0.01})
        assert resp.status == 200, f"vulnerable twin rejected the request: {resp.body}"
        body = json.loads(resp.body)
        assert body["plan_tier"] == "standard"
        assert body["monthly_charge"] == 0.01, (
            f"vulnerable twin should have trusted the manipulated client price: {resp.body}"
        )


def test_secure_twin_ignores_the_manipulated_client_price_and_charges_the_real_rate() -> None:
    """The same manipulated request against the secure twin must result in
    the correct, server-computed Standard price ($15.49) regardless of what
    the client sent."""
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0010"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        resp = _post_json(harness, {"plan_tier": "standard", "monthly_charge": 0.01})
        assert resp.status == 200, f"secure twin rejected the request: {resp.body}"
        body = json.loads(resp.body)
        assert body["plan_tier"] == "standard"
        assert body["monthly_charge"] == 15.49, (
            f"secure twin should have ignored the client price and charged the real rate: {resp.body}"
        )


def test_secure_twin_lookup_is_genuinely_data_driven_not_a_disguised_constant() -> None:
    """A second, distinct plan_tier must yield a different real price -- the
    same proof style `CC-LAB-0212`'s own `room_type=deluxe` case established
    for `php_laravel`'s twin, applied here so this is not silently accepted
    on the basis of one tier alone."""
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0010"]

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        basic_resp = _post_json(harness, {"plan_tier": "basic", "monthly_charge": 999.99})
        assert basic_resp.status == 200, basic_resp.body
        assert json.loads(basic_resp.body)["monthly_charge"] == 6.99

        premium_resp = _post_json(harness, {"plan_tier": "premium", "monthly_charge": 0.01})
        assert premium_resp.status == 200, premium_resp.body
        assert json.loads(premium_resp.body)["monthly_charge"] == 22.99


def test_secure_twin_fails_closed_on_an_unrecognized_plan_tier() -> None:
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0010"]

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        resp = _post_json(harness, {"plan_tier": "ultra-deluxe-not-real", "monthly_charge": 0.01})
        assert resp.status == 400, f"secure twin should reject an unrecognized plan_tier: {resp.body}"
