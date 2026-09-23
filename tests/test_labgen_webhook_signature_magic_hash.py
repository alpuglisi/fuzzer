"""Real, PHP-executed proof of the actual security differential
`CC-LAB-0133`'s webhook-signature-verification cell demonstrates -- PHP's
`==`/`!=` type-juggling ("magic hash") comparison bug, vs. `hash_equals()`.

**Why this exists separately from the live-boot test
(`test_labgen_webhook_signature_live_boot.py`).** A live HTTP test cannot
force the server's own freshly-computed `hash_hmac('sha256', ...)` output to
itself be a magic-hash-shaped string (probability on the order of
`(10/16)^62` -- not achievable by choosing the request body, since the
attacker doesn't control the value being compared against). This test
instead reproduces the *exact* comparison expressions the two generated
sinks use, against two real, independently well-documented "magic hash"
strings, executed by the real `php` interpreter -- proving the underlying
PHP-language-semantics fact the vulnerability class rests on, not a Python
simulation of it.

Skip-guarded (PA-0005) on `php_available()` (the plain `php` CLI, not the
full live-boot stack -- this test needs no Laravel project, no Composer,
no network).
"""

from __future__ import annotations

import subprocess

import pytest

from fuzzlab.labgen.conformance.tier0 import php_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not php_available(), reason="php CLI not available on this build host (PA-0005 pattern)"
)

#: Two real, independently published PHP "magic hash" strings: both match
#: `^0e[0-9]+$`, so PHP's numeric-string coercion treats both as the value
#: `0`, making `==`/`!=` compare them as numbers rather than as raw bytes --
#: despite being two different, unrelated strings. (Originally documented as
#: MD5 magic-hash collisions; the property this test exercises -- the
#: `0e<digits>` *shape* -- is independent of which hash function originally
#: produced them.)
_MAGIC_A = "0e830400451993494058024219903391"
_MAGIC_B = "0e291242476940776845150308577824"


def _run_php(expression: str) -> str:
    result = subprocess.run(
        ["php", "-r", f"var_dump({expression});"],
        capture_output=True,
        text=True,
        timeout=10.0,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_the_two_magic_hash_strings_are_genuinely_different() -> None:
    assert _MAGIC_A != _MAGIC_B


def test_php_treats_the_two_magic_hash_strings_as_loosely_equal() -> None:
    """The precondition the whole bug rests on: PHP's own `==` considers
    these two different strings equal."""
    assert _run_php(f"'{_MAGIC_A}' == '{_MAGIC_B}'") == "bool(true)"


def test_vulnerable_sink_operator_would_incorrectly_accept_the_collision() -> None:
    """Reproduces `LooseEqualityCompareTransform`'s exact rendered
    expression (`$__expectedSignature != $__webhookSignature`): with the two
    magic-hash strings standing in for "the real HMAC" and "the attacker's
    forged signature," this evaluates to `false` -- no mismatch detected, so
    the generated code's `if (...) { reject }` guard would NOT fire, and the
    forged request would be wrongly accepted."""
    assert _run_php(f"'{_MAGIC_A}' != '{_MAGIC_B}'") == "bool(false)"


def test_secure_sink_operator_correctly_rejects_the_collision() -> None:
    """Reproduces `ConstantTimeCompareTransform`'s exact rendered expression
    (`!hash_equals($__expectedSignature, $__webhookSignature)`): `hash_equals()`
    does real byte comparison, never type-juggles, so this correctly
    evaluates to `true` -- the mismatch guard fires and the secure twin
    rejects the same forged pair the vulnerable twin would accept."""
    assert _run_php(f"!hash_equals('{_MAGIC_A}', '{_MAGIC_B}')") == "bool(true)"


def test_generated_vulnerable_sink_actually_uses_the_bare_inequality_operator() -> None:
    """Confirms the emitter's real output is what the PHP-level tests above
    reproduce -- not a stale docstring claim."""
    manifest = load_manifest("lab/manifests/webhook_signature_huddlehub_sample.yaml")
    emitter = LaravelEmitter()
    cell = {c.cell_id: c for c in manifest.cells}["LABGEN-HHB-0001"]
    source = emitter.render(cell)[0].content.decode("utf-8")
    assert "!= $__webhookSignature" in source
    assert "hash_equals(" not in source


def test_generated_secure_sink_actually_uses_hash_equals() -> None:
    manifest = load_manifest("lab/manifests/webhook_signature_huddlehub_sample.yaml")
    emitter = LaravelEmitter()
    cell = {c.cell_id: c for c in manifest.cells}["LABGEN-HHB-0002"]
    source = emitter.render(cell)[0].content.decode("utf-8")
    assert "hash_equals($__expectedSignature, $__webhookSignature)" in source
