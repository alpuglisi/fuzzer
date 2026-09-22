"""Real, executed live-boot proof for `go_net_http` (category 4 pilot,
`CC-LAB-0090`/`FR-LAB-64`, Phase A). Mirrors
`tests/test_labgen_ruby_rails_live_boot.py`'s convention: skip-guarded on
the real capability probe (never a bare socket check -- `PA-0035`/
`BUG-0033`), one real assemble+build+boot+HTTP round trip proving a real
payload differential end to end.

**What "payload differential" means for this shape.** Unlike SQLi/XSS
(where the vulnerable/secure twins diverge on a *malicious* payload and
agree on a *benign* one), this stack's one illustrative shape is a boolean
signature check: both twins must accept a **correct** signature and reject
an **incorrect** one -- that functional behavior is identical by
construction (`lab/safety_matrix.yaml`'s `webhook_signature_verification`
family: `naive_string_compare` is `partial`, not `no_effect` -- it still
performs a real, correct comparison, just not a constant-time one). What
this test proves is exactly that shared functional contract holding for
both twins against a *real* boot -- the CWE-347 timing-side-channel
property itself is not empirically provable by a single-request functional
oracle and is not claimed to be here (the same honesty rule already applied
to other non-functional-oracle classes, e.g. CWE-1333/ReDoS, in this
category's own Walmart research note).
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.schema import load_manifest

_SHARED_SECRET = b"fuzzlab-go-net-http-lab-fixed-demo-secret"


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_correct_and_incorrect_signature_for_both_twins() -> None:
    manifest = load_manifest("lab/manifests/webhook_signature_go_sample.yaml")
    emitter = GoEmitter()
    body = b'{"event":"channel.follow","broadcaster":"twitch_lab"}'
    correct_digest = hmac.new(_SHARED_SECRET, body, hashlib.sha256).hexdigest()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        for cell_id, path in (
            ("LABGEN-GO-0001", "/generated/labgen-go-0001"),  # vulnerable: naive ==
            ("LABGEN-GO-0002", "/generated/labgen-go-0002"),  # secure: hmac.Equal
        ):
            ok = harness.post(path, body=body, headers={"X-Signature-256": correct_digest})
            assert ok.status == 200, f"{cell_id}: correct signature was rejected"

            bad = harness.post(path, body=body, headers={"X-Signature-256": "0" * 64})
            assert bad.status == 401, f"{cell_id}: incorrect signature was accepted"

            missing = harness.post(path, body=body, headers={})
            assert missing.status == 401, f"{cell_id}: missing signature header was accepted"
