"""Real, on-host verification of CC-LAB-0074's CWE-502 insecure-
deserialization pair (``ruby_rails``): assembles the real generated Rails
app, runs a real ``bundle install``, boots a real ``bin/rails server``, and
sends a real HTTP POST whose body carries an adversarial YAML payload with a
`!ruby/object:...` tag -- CVE-2013-0156's own mechanism (Psych's
`init_with` hook), applied here directly against a bulk-import-style POST
endpoint rather than through Rails' historical XML-parameter-parser entry
point.

The observable divergence: under `YAML.unsafe_load` the tag is honored and
a real `OpenStruct` object is actually constructed server-side (reported
back as the parsed value's real Ruby class name); under `YAML.safe_load`
the same tag is rejected with `Psych::DisallowedClass` before any object is
built. `require "ostruct"` in the generated app's `ApplicationController`
(this lane's own addition -- see that file) is what makes `OpenStruct`
loadable at all; both twins load it, since requiring a stdlib class is not
itself the vulnerability.

Skip-guarded (PA-0005/PA-0035) on `rails_boot_available()`. Marked
`@pytest.mark.slow`. Each cell gets its own fresh `RailsLiveBootHarness` --
this shape needs no shared database state, but a fresh harness per cell is
still this project's own convention (mirrors the mass-assignment live-boot
test's own reasoning).
"""

from __future__ import annotations

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

MANIFEST_PATH = "lab/manifests/insecure_deserialization_rails_sample.yaml"

#: A real, minimal YAML payload carrying Psych's own object-instantiation
#: tag syntax -- constructs a real, harmless-in-isolation `OpenStruct`
#: (never a gadget chain/RCE payload: this project's own lab-only, non-
#: adversarial-target policy (CLAUDE.md's Safety section) means this proof
#: only needs to show *that* an arbitrary object type is constructed, the
#: same property CVE-2013-0156's own disclosure turns into RCE via a gadget
#: this lab never builds or needs).
_ADVERSARIAL_YAML_PAYLOAD = "--- !ruby/object:OpenStruct\ntable:\n  :pwned: true\n"


@pytest.mark.slow
def test_vulnerable_unsafe_load_constructs_the_tagged_object() -> None:
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    vulnerable = cells["LABGEN-RR-0006"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with RailsLiveBootHarness(emitter, [vulnerable]) as harness:
        resp = harness.post("/cell/labgen_rr_0006", data={"yaml_payload": _ADVERSARIAL_YAML_PAYLOAD})
        assert resp.status == 200, resp.body
        body = json.loads(resp.body)
        assert body["ok"] is True
        # The real finding: an attacker-chosen Ruby class was actually
        # instantiated server-side from tainted YAML input.
        assert body["parsed_class"] == "OpenStruct"


@pytest.mark.slow
def test_secure_safe_load_rejects_the_tagged_object() -> None:
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    secure = cells["LABGEN-RR-0007"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with RailsLiveBootHarness(emitter, [secure]) as harness:
        resp = harness.post("/cell/labgen_rr_0007", data={"yaml_payload": _ADVERSARIAL_YAML_PAYLOAD})
        assert resp.status == 200, resp.body
        body = json.loads(resp.body)
        assert body["ok"] is False
        # Psych's own restricted loader rejects the tag before building
        # anything -- no OpenStruct (or any other non-scalar/array/hash
        # object) is ever constructed.
        assert body["error"] == "Psych::DisallowedClass"


@pytest.mark.slow
def test_both_twins_still_parse_ordinary_plain_yaml_identically() -> None:
    """The minimal-pair invariant, proven over a real HTTP round trip, not
    just template text: for *ordinary* YAML with no object tag, both twins
    behave identically (Psych's safe subset is not "broken" for plain data --
    only the unrestricted object-graph path is the vulnerability)."""
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    plain_payload = "greeting: hello\ncount: 3\n"

    with RailsLiveBootHarness(emitter, [cells["LABGEN-RR-0006"]]) as harness:
        vuln_resp = harness.post("/cell/labgen_rr_0006", data={"yaml_payload": plain_payload})
    with RailsLiveBootHarness(emitter, [cells["LABGEN-RR-0007"]]) as harness:
        secure_resp = harness.post("/cell/labgen_rr_0007", data={"yaml_payload": plain_payload})

    assert json.loads(vuln_resp.body) == {"ok": True, "parsed_class": "Hash"}
    assert json.loads(secure_resp.body) == {"ok": True, "parsed_class": "Hash"}
