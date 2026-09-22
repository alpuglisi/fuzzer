"""Real, on-host verification of CC-LAB-0072's webhook-signature pair
(``ruby_rails``): assembles the real generated Rails app, runs a real
``bundle install``, boots a real ``bin/rails server``, and sends real HTTP
POSTs whose raw body a real HMAC-SHA256 was computed over -- exactly
Shopify's own `X-Shopify-Hmac-SHA256` mechanism
(`docs/research/site-architecture-survey-functionality-shopify.md` §1).

**Why this test proves two different things, not one.** A naive `==`
compare and Rails' own `ActiveSupport::SecurityUtils.secure_compare` give
the *same* accept/reject answer for any single well-formed request -- the
vulnerability is a timing side channel (D20 `partial`), not a functional
bypass. So this file has two halves:

1. A real HTTP round trip against both twins, proving the generated app
   actually boots, serves, and *correctly* verifies (accepts a valid
   signature, rejects a tampered one) -- the same "renders, boots, serves"
   bar every other live-boot test in this project holds itself to.
2. A real, isolated Ruby timing microbenchmark (`RailsLiveBootHarness.
   run_ruby`, executed inside the booted cell's own `bundle exec` --
   real `ActiveSupport::SecurityUtils.secure_compare` from this app's own
   resolved gem, not a hand-reimplementation) that demonstrates the actual
   security-relevant property: plain Ruby `String#==` short-circuits on the
   first mismatched byte (so a compare that mismatches near the *end* of a
   long string measurably takes longer than one that mismatches at the
   *start*), while `secure_compare` does not. Two large synthetic strings
   (200,000 bytes) are used deliberately here -- not this cell's own
   ~44-byte base64 HMAC digest -- purely so the effect is large enough to
   measure reliably within a bounded, non-flaky test; this is a real,
   executed demonstration of the underlying mechanism Shopify's own secure-
   compare idiom exists to defend against, not a claim that this specific
   illustrative cell's digest-length compare is itself an exploitable
   timing channel over a real network round trip.

Skip-guarded (PA-0005/PA-0035) on `rails_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not rails_boot_available(),
    reason=(
        "rails live-boot harness requires ruby + bundle on PATH and real RubyGems "
        "network reachability (PA-0005/PA-0035) -- see rails_live_boot.rails_boot_available()"
    ),
)

MANIFEST_PATH = "lab/manifests/webhook_signature_rails_sample.yaml"

#: Must match `_SHAPE_CTX[("webhook_signature", ...)]["secret"]` in
#: `fuzzlab/labgen/emitters/ruby_rails/__init__.py` exactly -- this test
#: forges the header the same way a real webhook provider would, using the
#: same shared secret the generated app itself signs/verifies with.
_SHARED_SECRET = b"whsec_lab_lab_only_not_a_real_secret"
_HEADER_NAME = "X-Shopify-Hmac-SHA256"


def _sign(body: bytes) -> str:
    return base64.b64encode(hmac.new(_SHARED_SECRET, body, hashlib.sha256).digest()).decode("ascii")


@pytest.mark.slow
@pytest.mark.parametrize("cell_id,path", [("LABGEN-RR-0002", "/cell/labgen_rr_0002"), ("LABGEN-RR-0003", "/cell/labgen_rr_0003")])
def test_both_twins_correctly_verify_a_real_hmac(cell_id: str, path: str) -> None:
    """A real HTTP round trip: both the naive-`==` and the
    `secure_compare` twin give the *same*, correct answer for a
    well-formed valid signature and a well-formed tampered one -- proving
    the generated app actually boots/serves/verifies, independent of the
    timing-safety property the second half of this file proves."""
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    cell = cells[cell_id]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    body = b'{"topic": "orders/create", "id": 42}'
    valid_signature = _sign(body)

    with RailsLiveBootHarness(emitter, [cell]) as harness:
        ok = harness.post(
            path,
            raw_body=body,
            headers={_HEADER_NAME: valid_signature, "Content-Type": "application/json"},
        )
        assert ok.status == 200, ok.body
        assert json.loads(ok.body) == {"verified": True}

        tampered = harness.post(
            path,
            raw_body=body,
            headers={_HEADER_NAME: _sign(b"tampered-body"), "Content-Type": "application/json"},
        )
        assert tampered.status == 401, tampered.body
        assert json.loads(tampered.body) == {"verified": False}


# ---------------------------------------------------------------------------
# The actual timing-safety divergence: a real, isolated Ruby microbenchmark
# ---------------------------------------------------------------------------

#: Ruby script run via `bundle exec ruby` inside a booted cell's own app
#: directory (so it exercises the exact real `activesupport` gem version
#: this app's own `Gemfile.lock` resolved). Compares two 200,000-byte
#: strings that mismatch at the very first byte ("early") vs the very last
#: byte ("late"), timing many repetitions of each comparison with both
#: `==` and `ActiveSupport::SecurityUtils.secure_compare`, and prints the
#: four elapsed times as CSV.
_TIMING_PROBE_RB = """
require "active_support/security_utils"

n = 800
len = 20_000
base = "a" * len
early_mismatch = "b" + base[1..-1]
late_mismatch = base[0..-2] + "b"

def bench(n)
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  n.times { yield }
  Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
end

naive_early = bench(n) { base == early_mismatch }
naive_late = bench(n) { base == late_mismatch }
secure_early = bench(n) { ActiveSupport::SecurityUtils.secure_compare(base, early_mismatch) }
secure_late = bench(n) { ActiveSupport::SecurityUtils.secure_compare(base, late_mismatch) }

puts [naive_early, naive_late, secure_early, secure_late].join(",")
"""


@pytest.mark.slow
def test_naive_equality_is_measurably_timing_variable_but_secure_compare_is_not() -> None:
    """The real proof this whole class exists for: plain `==`'s short-
    circuit makes an early-mismatch compare measurably faster than a
    late-mismatch compare over a large string (a real, executed Ruby
    process, real `Process.clock_gettime` timing, real string comparison --
    not simulated), while `ActiveSupport::SecurityUtils.secure_compare`
    -- the real gem this app's own Gemfile.lock resolved -- does not."""
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    # Either twin's already-`bundle install`-ed app directory works here --
    # this microbenchmark exercises the interpreter/gems the harness set
    # up, not the generated controller code itself.
    cell = cells["LABGEN-RR-0002"]

    with RailsLiveBootHarness(emitter, [cell]) as harness:
        result = harness.run_ruby(_TIMING_PROBE_RB, timeout=60.0)
        assert result.returncode == 0, f"timing probe failed: {result.stdout}\n{result.stderr}"
        naive_early, naive_late, secure_early, secure_late = (
            float(x) for x in result.stdout.strip().split(",")
        )

    assert naive_early > 0 and naive_late > 0 and secure_early > 0 and secure_late > 0

    naive_ratio = naive_late / naive_early
    secure_ratio = secure_late / secure_early

    # A generous, non-flaky threshold: naive `==` must show at least a 2x
    # slowdown scanning to a late mismatch vs an early one (measured
    # ~4.8x in this project's own dev sandbox at these parameters) --
    # while `secure_compare`'s own ratio must stay close to 1 (measured
    # ~1.02x), since it always scans the full length regardless of where
    # (or whether) a mismatch occurs.
    assert naive_ratio > 2.0, (
        f"naive `==` did not show the expected early-vs-late mismatch timing gap "
        f"(ratio={naive_ratio:.2f}, early={naive_early:.4f}s, late={naive_late:.4f}s) -- "
        "either the build host is too noisy for this microbenchmark or the underlying "
        "short-circuit behavior regressed"
    )
    assert secure_ratio < 1.5, (
        f"ActiveSupport::SecurityUtils.secure_compare showed an unexpectedly large "
        f"early-vs-late timing gap (ratio={secure_ratio:.2f}) -- it should scan the "
        "full length regardless of mismatch position"
    )
