"""Real, executed live-boot proof for Netflix's seventh real page
(`CC-LAB-0192`, `FR-LAB-132`): this stack's first `mass_assignment`
instance, an account-settings-update endpoint at
`POST /api/account/settings`.

Mirrors `tests/test_labgen_go_live_boot.py`'s own
`test_real_boot_proves_the_mass_assignment_differential_for_both_twins`/
`test_real_boot_proves_the_mass_assignment_strategy_end_to_end`
(`CC-LAB-0182`/`CC-FUZZ-0035`) -- the same differential-then-strategy shape,
ported to this stack's own `SpringBootLiveBootHarness` (one cell per harness
instance, so each twin gets its own boot).

A second test class (`Test...GeneralizesToSpringBoot`) proves
`MassAssignmentPrivilegedFieldStrategy` (already built for Twitch's
`TWCH-0006`/`CC-AUD-0022`/`CC-FUZZ-0035`) needs zero new detection code to
confirm this new `spring_boot` vulnerable twin and correctly fail closed on
its secure twin -- the first proof this strategy generalizes across stacks
(`go_net_http` -> `spring_boot`), the same direction `CC-LAB-0187`'s own
`AccessControlIdorStrategy` proof and `CC-LAB-0191`'s own
`UnrestrictedFileUploadContentTypeTrustStrategy` proof already established
for other vuln classes on this exact app.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
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
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import MassAssignmentPrivilegedFieldStrategy

_MANIFEST_PATH = "lab/manifests/mass_assignment_netflix_settings_sample.yaml"
_ROUTE = "/api/account/settings"

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

_BODY = json.dumps({"display_name": "new_name", "bio": "hi", "is_partner": True}).encode("utf-8")


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def test_real_boot_proves_the_mass_assignment_differential_for_both_twins() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0013"]) as harness:
        resp = harness.request("POST", _ROUTE, data=_BODY, content_type="application/json")
        assert resp.status == 200, f"vulnerable twin rejected the request: {resp.body}"
        record = json.loads(resp.body)
        assert record["display_name"] == "new_name"
        assert record["bio"] == "hi"
        assert record["is_partner"] is True, (
            "vulnerable twin did not honor the privileged is_partner field -- "
            "not actually mass-assignable"
        )

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0014"]) as harness:
        resp = harness.request("POST", _ROUTE, data=_BODY, content_type="application/json")
        assert resp.status == 200, f"secure twin rejected the request: {resp.body}"
        record = json.loads(resp.body)
        assert record["display_name"] == "new_name"
        assert record["bio"] == "hi"
        assert record["is_partner"] is False, (
            "secure twin incorrectly let is_partner through its allowlist"
        )


class TestMassAssignmentPrivilegedFieldStrategyGeneralizesToSpringBoot:
    """Proves `MassAssignmentPrivilegedFieldStrategy` needs zero new
    detection code to confirm this new `spring_boot` vulnerable twin and
    correctly fail closed on its secure twin."""

    def _candidate(self) -> Candidate:
        return Candidate(
            url="http://h" + _ROUTE, param="body", method="POST", location="body",
            vuln_class="mass_assignment", category="mass-assignment",
            content_type="application/json",
        )

    def test_confirms_the_vulnerable_twin(self) -> None:
        emitter = SpringBootEmitter()
        vulnerable = _cells()["LABGEN-JV-0013"]
        strategy = MassAssignmentPrivilegedFieldStrategy()

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="POST",
                          location="body", content_type=None):
                    resp = harness.request(
                        "POST", _ROUTE, data=value.encode("utf-8"), content_type="application/json"
                    )
                    return Probe(resp.status, resp.body)

            verdict = strategy.confirm(self._candidate(), _HarnessSender())
            assert verdict is not None and verdict.confirmed, (
                "strategy failed to confirm the real vulnerable spring_boot twin"
            )
            assert verdict.vuln_class == "mass_assignment"

    def test_fails_closed_on_the_secure_twin(self) -> None:
        emitter = SpringBootEmitter()
        secure = _cells()["LABGEN-JV-0014"]
        strategy = MassAssignmentPrivilegedFieldStrategy()

        with SpringBootLiveBootHarness(emitter, secure) as harness:
            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="POST",
                          location="body", content_type=None):
                    resp = harness.request(
                        "POST", _ROUTE, data=value.encode("utf-8"), content_type="application/json"
                    )
                    return Probe(resp.status, resp.body)

            assert strategy.confirm(self._candidate(), _HarnessSender()) is None, (
                "strategy incorrectly confirmed the secure spring_boot twin"
            )
