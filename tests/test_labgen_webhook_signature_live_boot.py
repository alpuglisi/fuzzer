"""Live-boot conformance check for `php_laravel`'s webhook-signature-
verification cell (`CC-LAB-0133`, Huddle Hub -- category 3's Slack pick).

Real, on-host integration test: assembles a real Laravel 13 project from
the checked-in skeleton plus this manifest's real `LaravelEmitter` output,
runs a real `composer install`, boots a real `php artisan serve`, and sends
real HTTP POSTs against it -- one cell per harness instance (the twins
share a route), mirroring `mass_assignment_laravel_sample.yaml`'s own
twin-pair precedent.

**What this proves, and what it deliberately does not (see `CC-LAB-0133`'s
change-control entry for the full reasoning).** This test proves ordinary
functional correctness only: a correctly-computed HMAC signature is
accepted on both twins, and an ordinary wrong signature is rejected on
both twins (the `loose_equality_compare` bug does not fire for an ordinary
wrong value -- only for a magic-hash-shaped one, which a live HTTP test
cannot force the server's own freshly-computed SHA-256 HMAC output to be).
The actual security differential (the vulnerable twin's `!=` operator
incorrectly treating two different "magic hash"-shaped strings as equal,
while the secure twin's `hash_equals()` does not) is proven separately,
without a live boot, in `test_labgen_webhook_signature_magic_hash.py` --
a real PHP-executed proof of the operator semantics themselves.

Skip-guarded (PA-0005) on `live_boot_available()`. Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)

#: Matches the fixed, lab-only secret both templates render into the
#: generated controllers -- see `php_laravel/__init__.py`'s
#: `/webhooks/events` page profile.
_SECRET = "lab-only-huddlehub-webhook-secret"
_BODY_FIELD = "event"
_BODY_VALUE = "message.posted"


def _real_signature_for(data: dict[str, str]) -> str:
    """The exact signature the generated PHP would compute for this exact
    form-encoded body -- `LiveBootHarness.post()`'s own `urlencode(data)`,
    reproduced here so this test can send a signature the server will
    consider genuinely correct."""
    import urllib.parse

    raw_body = urllib.parse.urlencode(data).encode("utf-8")
    return hmac.new(_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def _cells():
    manifest = load_manifest("lab/manifests/webhook_signature_huddlehub_sample.yaml")
    return {c.cell_id: c for c in manifest.cells}


@pytest.mark.slow
def test_webhook_signature_vulnerable_twin_accepts_a_correct_signature() -> None:
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0001"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        data = {_BODY_FIELD: _BODY_VALUE}
        resp = harness.post(url, data=data, headers={"X-Signature": _real_signature_for(data)})
        assert resp.status == 200, resp.body
        assert '"accepted"' in resp.body, resp.body


@pytest.mark.slow
def test_webhook_signature_vulnerable_twin_rejects_an_ordinary_wrong_signature() -> None:
    """A plain, non-numeric-string wrong signature must still be rejected --
    the `loose_equality_compare` bug is real but narrow (only fires for a
    magic-hash-shaped collision, see this module's own docstring), not a
    total bypass."""
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0001"]

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        data = {_BODY_FIELD: _BODY_VALUE}
        resp = harness.post(url, data=data, headers={"X-Signature": "not-the-right-signature"})
        assert resp.status == 403, resp.body


@pytest.mark.slow
def test_webhook_signature_secure_twin_accepts_a_correct_signature_and_rejects_a_wrong_one() -> None:
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-HHB-0002"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        data = {_BODY_FIELD: _BODY_VALUE}

        good_resp = harness.post(url, data=data, headers={"X-Signature": _real_signature_for(data)})
        assert good_resp.status == 200, good_resp.body
        assert '"accepted"' in good_resp.body, good_resp.body

        bad_resp = harness.post(url, data=data, headers={"X-Signature": "not-the-right-signature"})
        assert bad_resp.status == 403, bad_resp.body
