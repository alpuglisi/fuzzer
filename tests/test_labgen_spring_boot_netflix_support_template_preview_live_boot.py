"""Real, executed live-boot proof for Netflix's eleventh real page
(`CC-LAB-0197`, `FR-LAB-152`): this stack's first `ssti`/`template_render`
instance on THIS app identity, a customer-support-agent template-preview
endpoint at `GET /api/support/template-preview?expr=`.

Mirrors `tests/test_labgen_spring_boot_live_boot.py`'s own
`test_ssti_vulnerable_twin_evaluates_ognl_expression_for_real`/
`test_ssti_secure_twin_never_evaluates_the_tainted_value` (`CC-LAB-0130`) --
the same OGNL `7*7` -> `49` differential proof, ported to a new,
Netflix-specific route on the shared `spring_boot` package.

A second test class (`TestSstiStrategyGeneralizesToNetflix`) proves the
existing generic `SstiStrategy` (`fuzzlab/oracle/strategies.py`, already
built and live-boot-confirmed against TrackerNest's own `/wiki/pages/render`
cell, `TNEST-0001`/`CC-CORE-0020`) needs zero new detection code to confirm
this new Netflix vulnerable twin and correctly fail closed on its secure
twin -- the same generalization direction (a mechanism already proven on
one app identity sharing this package, reused verbatim on the other) this
session's own cross-stack-generalization campaign has repeatedly proven for
other vuln classes on this exact app (`CC-LAB-0187`'s
`AccessControlIdorStrategy`, `CC-LAB-0191`'s
`UnrestrictedFileUploadContentTypeTrustStrategy`, `CC-LAB-0192`'s
`MassAssignmentPrivilegedFieldStrategy`, `CC-LAB-0193`'s
`JwtAlgNoneConfusionStrategy`, `CC-LAB-0194`'s `SsrfInBandMarkerStrategy`/
`SsrfOobStrategy`, `CC-LAB-0195`'s `PredictableTokenSourceStrategy`) --
unlike `CC-FUZZ-0042`'s `GoTemplateSstiStrategy` follow-on, this shape
(Java/OGNL, which DOES support the arithmetic-product marker payloads
`SstiStrategy._ssti_payloads()` sends) generalizes for free, so this test
proves that expectation empirically rather than assuming it from the shape
match alone.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

_MANIFEST_PATH = "lab/manifests/ssti_netflix_support_sample.yaml"
_ROUTE = "/api/support/template-preview"

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


def test_ssti_vulnerable_twin_evaluates_ognl_expression_for_real() -> None:
    """The vulnerable cell (`user_supplied_template_compile`) must actually
    evaluate an attacker-supplied arithmetic OGNL expression server-side,
    on this new Netflix-specific route -- the same `7*7` -> `49` proof
    `CC-LAB-0130`'s own TrackerNest test established."""
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0021"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = harness.get(_ROUTE, params={"expr": "7*7"})
        assert resp.status == 200, resp.body
        assert "49" in resp.body, resp.body


def test_ssti_secure_twin_never_evaluates_the_tainted_value() -> None:
    """The secure cell (`file_loaded_template_name`) must treat the same
    tainted value as a preview-template **name** only: `7*7` never
    evaluates (it is simply an unrecognized template name), while a real,
    fixed, developer-defined template name still resolves to its real
    fixed body -- proving the secure twin's lookup path actually runs, not
    merely that evaluation is absent."""
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0022"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        injection_resp = harness.get(_ROUTE, params={"expr": "7*7"})
        assert injection_resp.status == 200, injection_resp.body
        assert "49" not in injection_resp.body, injection_resp.body
        assert "Unknown macro" in injection_resp.body, injection_resp.body

        legitimate_resp = harness.get(_ROUTE, params={"expr": "welcome"})
        assert legitimate_resp.status == 200, legitimate_resp.body
        assert "Welcome to the team wiki!" in legitimate_resp.body, legitimate_resp.body


class TestSstiStrategyGeneralizesToNetflix:
    """Proves the existing generic `SstiStrategy` (already built and
    live-boot-confirmed against TrackerNest's own `/wiki/pages/render`
    cell) needs zero new detection code to confirm this new Netflix
    vulnerable twin and correctly fail closed on its secure twin."""

    def _candidate(self):
        from fuzzlab.oracle.probe import Candidate
        return Candidate(
            url="http://h" + _ROUTE, param="expr", method="GET", location="query",
            vuln_class="ssti", category="server-side-template-injection",
        )

    def test_confirms_the_vulnerable_twin(self) -> None:
        from fuzzlab.oracle.probe import Probe
        from fuzzlab.oracle.strategies import SstiStrategy

        emitter = SpringBootEmitter()
        vulnerable = _cells()["LABGEN-JV-0021"]

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:

            class _HarnessSender:
                def send(self, url, param, value, timing=False):
                    resp = harness.get(_ROUTE, params={param: value})
                    return Probe(resp.status, resp.body)

            verdict = SstiStrategy().confirm(self._candidate(), _HarnessSender())
            assert verdict is not None and verdict.confirmed, (
                "SstiStrategy failed to confirm the real vulnerable Netflix "
                "spring_boot ssti/template_render twin"
            )
            assert verdict.vuln_class == "ssti"

    def test_fails_closed_on_the_secure_twin(self) -> None:
        from fuzzlab.oracle.probe import Probe
        from fuzzlab.oracle.strategies import SstiStrategy

        emitter = SpringBootEmitter()
        secure = _cells()["LABGEN-JV-0022"]

        with SpringBootLiveBootHarness(emitter, secure) as harness:

            class _HarnessSender:
                def send(self, url, param, value, timing=False):
                    resp = harness.get(_ROUTE, params={param: value})
                    return Probe(resp.status, resp.body)

            assert SstiStrategy().confirm(self._candidate(), _HarnessSender()) is None, (
                "SstiStrategy incorrectly confirmed the secure Netflix "
                "spring_boot ssti/template_render twin"
            )
