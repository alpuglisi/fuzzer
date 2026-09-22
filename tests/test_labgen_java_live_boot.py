"""Real, executed live-boot proof for `java_spring_boot` (category 4
pilot, `CC-LAB-0171`/`FR-LAB-77`, Phase A). Mirrors
`tests/test_labgen_go_live_boot.py`'s convention: skip-guarded on the real
capability probe (never a bare socket check -- `PA-0035`/`BUG-0033`), one
real assemble+package+boot+HTTP round trip proving a real, observable
code-path differential end to end.

**What this proves, concretely (verified against a real boot this
session, not assumed).** Jackson's `activateDefaultTyping()` changes what
JSON *shape* the vulnerable endpoint accepts: with default typing active,
Jackson expects (and requires) an embedded type hint -- a
`["<fully-qualified-class-name>", {...}]`-shaped body -- and uses that
attacker-supplied class name to pick the concrete type it instantiates.
The secure twin's fixed-DTO deserializer has no such polymorphic
type-selection step at all: it accepts a plain, flat JSON object matching
`PlaybackResumeRequest`'s own fields, and rejects the type-hint-wrapped
shape the vulnerable twin requires. This test asserts exactly that
observable, real difference -- **not** a working `ysoserial`-style RCE
gadget chain (neither twin has one on its classpath; see
`CC-LAB-0171`'s change-control entry for why that is a deliberate,
declared scope boundary, not an oversight) and **not** a timing side
channel (CWE-502 has none to prove here) -- the same honest "code-path
proof, not a working exploit" scoping `CC-LAB-0170`'s own live-boot test
used for CWE-347's non-functional timing property.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.java_live_boot import JavaLiveBootHarness, java_boot_available
from fuzzlab.labgen.emitters.java_spring_boot import JavaEmitter
from fuzzlab.labgen.schema import load_manifest

#: A body carrying an attacker-chosen type hint Jackson's default typing
#: will honor -- `java.util.HashMap`, a real, always-on-the-classpath JDK
#: class chosen here only to demonstrate that *the vulnerable endpoint
#: lets the request body pick the class*, not to demonstrate a gadget
#: chain (HashMap is inert).
_POLYMORPHIC_TYPE_HINT_BODY = b'["java.util.HashMap",{"profileId":"p1"}]'

#: A plain, flat JSON body matching `PlaybackResumeRequest`'s own fields --
#: what the secure twin's fixed-DTO deserializer actually expects.
_PLAIN_BODY = b'{"profileId":"p1","eventType":"resume","positionMs":1200}'

_JSON_HEADERS = {"Content-Type": "application/json"}


@pytest.mark.slow
@pytest.mark.skipif(
    not java_boot_available(), reason="mvn/java toolchain/Maven Central not available (PA-0035 pattern)"
)
def test_real_boot_proves_the_deserialization_code_path_differs() -> None:
    manifest = load_manifest("lab/manifests/insecure_deserialization_java_sample.yaml")
    emitter = JavaEmitter()

    with JavaLiveBootHarness(emitter, manifest.cells) as harness:
        # Vulnerable twin: a type-hint-wrapped body naming an arbitrary
        # class is accepted -- the request body dictates the deserialized
        # type, the CWE-502 shape itself.
        vuln_poly = harness.post(
            "/generated/labgen-jv-0001", body=_POLYMORPHIC_TYPE_HINT_BODY, headers=_JSON_HEADERS
        )
        assert vuln_poly.status == 200, (
            f"vulnerable twin rejected an attacker-type-hinted body (status {vuln_poly.status}) -- "
            "the vulnerable deserializer should accept caller-chosen types"
        )

        # Secure twin: the plain, well-formed body its fixed DTO expects
        # works normally.
        secure_plain = harness.post("/generated/labgen-jv-0002", body=_PLAIN_BODY, headers=_JSON_HEADERS)
        assert secure_plain.status == 200, (
            f"secure twin rejected its own well-formed request shape (status {secure_plain.status})"
        )

        # Secure twin: the same type-hint-wrapped body the vulnerable twin
        # accepted is rejected -- no polymorphic type selection exists on
        # this path at all.
        secure_poly = harness.post(
            "/generated/labgen-jv-0002", body=_POLYMORPHIC_TYPE_HINT_BODY, headers=_JSON_HEADERS
        )
        assert secure_poly.status != 200, (
            "secure twin accepted an attacker-type-hinted body -- it should have no polymorphic "
            "deserialization path to honor that hint on"
        )
