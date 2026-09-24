"""Real, executed live-boot proof that `UnrestrictedFileUploadContentType
TrustStrategy` (CC-AUD-0023/CC-FUZZ-0040) confirms the real vulnerable
`no_extension_check` twin and correctly fails closed on the real secure
`extension_allowlist_mime_check` twin -- `LABGEN-GO-0017`/`0018`
(`lab/manifests/unrestricted_file_upload_go_sample.yaml`, `CC-LAB-0186`),
driven through the real `RequestsProbeSender` this project already uses for
every other live-boot strategy proof (e.g.
`tests/test_labgen_go_live_boot.py`'s own `AccessControlIdorStrategy`/
`JwtAlgNoneConfusionStrategy` siblings), never a fake sender.

Filesystem safety: every write this test causes lands under
`GoLiveBootHarness`'s own throwaway `tempfile.TemporaryDirectory`-backed
process `cwd` (the generated handler's `static/emotes` path is relative,
resolved against that `cwd`) -- never a real, permanent, or shared path,
the same constraint `CC-LAB-0186`'s own live-boot test honors. The probe
payload the strategy sends is an inert `<!DOCTYPE html><p>FUZZLAB-MARKER-
...</p>` marker, never an executing `<script>` tag.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.probe import Candidate
from fuzzlab.oracle.strategies import UnrestrictedFileUploadContentTypeTrustStrategy
from fuzzlab.tools.probesender import RequestsProbeSender

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not go_boot_available(),
                       reason="go toolchain/module-proxy not available (PA-0035 pattern)"),
]


def _candidate(url: str) -> Candidate:
    return Candidate(url=url, param="file", method="POST", location="body",
                     vuln_class="unrestricted_file_upload",
                     category="unrestricted-file-upload", sink_context="fs_web_root_write")


def test_real_boot_confirms_the_vulnerable_twin_and_fails_closed_on_the_secure_twin() -> None:
    manifest = load_manifest("lab/manifests/unrestricted_file_upload_go_sample.yaml")
    emitter = GoEmitter()
    strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
    sender = RequestsProbeSender(timeout=10.0)

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        vuln_candidate = _candidate(harness.base_url + "/generated/labgen-go-0017")
        verdict = strategy.confirm(vuln_candidate, sender)
        assert verdict is not None and verdict.confirmed
        assert verdict.vuln_class == "unrestricted_file_upload"
        assert verdict.evidence["served_content_type"] == "image/svg+xml"
        assert verdict.evidence["control_content_type"] == "image/png"

        secure_candidate = _candidate(harness.base_url + "/generated/labgen-go-0018")
        assert strategy.confirm(secure_candidate, sender) is None
