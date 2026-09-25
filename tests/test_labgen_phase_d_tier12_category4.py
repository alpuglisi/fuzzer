"""Phase D -- Tier 1/2 conformance for category 4's currently-built cells
(`CC-LAB-0175`/`FR-LAB-81`). Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
§5: "run the proof," using Phase A/B's own live-boot harnesses as the real,
in-process `Tier1Client`/`Tier2Client` this project's shared
`fuzzlab.labgen.conformance.tier1`/`tier2` modules need -- never a new,
stack-specific proof mechanism.

Each stack gets a small local adapter class wrapping its own harness (the
harness classes' *existing*, already-tested `request`/`post` methods are
never modified here -- other tests depend on their current signatures);
`tier2.py`'s own docstring already anticipates this ("this module stays
usable against any future in-process client shaped the same way").

**Two of this category's three cells fit Tier 1/2's marker/functional-
differential model cleanly (SSRF, Jackson deserialization); the third
(webhook-signature) genuinely does not, and is not forced into it here --
see `test_labgen_go_live_boot.py`'s own docstring, which already states
the same honesty rule for this exact cell: "the CWE-347 timing-side-channel
property itself is not empirically provable by a single-request functional
oracle." A single request cannot distinguish a naive `==` compare from a
constant-time `hmac.Equal` compare -- both twins behave identically for any
one request, correct or incorrect signature alike (`lab/safety_matrix.yaml`:
`naive_string_compare` is `partial`, not `no_effect`). Tier 1/2 for this
cell is therefore an open question, not a todo -- see `FR-LAB-81`'s own note
in `docs/components/01-target-lab/requirements.md`.**
"""

from __future__ import annotations

import http.server
import socket
import threading
import urllib.parse

import pytest

from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.conformance.tier1 import Tier1Case, build_tier1_case, run_tier1_case
from fuzzlab.labgen.conformance.tier2 import LiveBootTier2Oracle, run_tier2_case
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.slow


# -- SSRF (go_net_http, LABGEN-GO-0003/0004) ---------------------------------


class _ThumbHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib override
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"thumb-bytes")

    def log_message(self, *args: object) -> None:  # silence per-request stderr noise
        pass


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_plain_http_listener() -> http.server.HTTPServer:
    """Same throwaway, self-owned loopback listener `test_labgen_go_live_boot.py`
    already uses for this exact shape -- lab-only, never a real external host."""
    server = http.server.HTTPServer(("127.0.0.1", _free_loopback_port()), _ThumbHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class _GoSsrfTier12Client:
    """A minimal `Tier1Client`/`Tier2Client` adapter over `GoLiveBootHarness`'s
    existing (unmodified) `request()` method -- this shape is GET-only."""

    def __init__(self, harness: GoLiveBootHarness) -> None:
        self._harness = harness

    def get(self, path: str, *, params: dict[str, str] | None = None):
        qs = urllib.parse.urlencode(params or {})
        return self._harness.request("GET", f"{path}?{qs}" if qs else path)

    def fetch(self, case: Tier1Case) -> str:
        assert case.location == "query"
        return self.get(case.path, params={case.param_name: case.payload}).body


@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_ssrf_tier1_and_tier2_confirm_both_twins() -> None:
    manifest = load_manifest("lab/manifests/ssrf_go_sample.yaml")
    emitter = GoEmitter()
    listener = _start_plain_http_listener()
    try:
        target_url = f"http://127.0.0.1:{listener.server_address[1]}/thumb"
        with GoLiveBootHarness(emitter, manifest.cells) as harness:
            client = _GoSsrfTier12Client(harness)
            cases = {
                "LABGEN-GO-0003": Tier1Case(  # vulnerable: unchecked_url_fetch
                    cell_id="LABGEN-GO-0003", method="GET", path="/api/clips/thumbnail",
                    param_name="url", location="query", payload=target_url,
                    evidence_marker="thumb-bytes", expected_vulnerable=True,
                ),
                "LABGEN-GO-0004": Tier1Case(  # secure: scheme_and_resolved_ip_allowlist
                    cell_id="LABGEN-GO-0004", method="GET", path="/api/clips/thumbnail.labgen-go-0004",
                    param_name="url", location="query", payload=target_url,
                    evidence_marker="thumb-bytes", expected_vulnerable=False,
                ),
            }
            for cell_id, case in cases.items():
                tier1 = run_tier1_case(case, client)
                assert tier1.matches_expectation, (
                    f"{cell_id}: Tier 1 mismatch -- expected_vulnerable="
                    f"{case.expected_vulnerable}, detected={tier1.vulnerable_detected}, "
                    f"body={tier1.response_excerpt!r}"
                )

                # An always-refused control (connection refused on loopback) never
                # shows the marker on either twin -- isolates "did the payload
                # itself cause the leak" from "does this app ever echo the marker".
                oracle = LiveBootTier2Oracle(client=client, control_value="http://127.0.0.1:1/")
                tier2 = run_tier2_case(case, oracle)
                assert tier2.matches_expectation, (
                    f"{cell_id}: Tier 2 mismatch -- expected_vulnerable="
                    f"{case.expected_vulnerable}, confirmed={tier2.confirmed_vulnerable}, "
                    f"detail={tier2.oracle_detail!r}"
                )
    finally:
        listener.shutdown()


# -- Insecure deserialization (spring_boot, LABGEN-JV-0001/0002) -------------

_MANIFEST_PATH = "lab/manifests/insecure_deserialization_spring_boot_sample.yaml"
_ROUTE = "/api/playback/resume"
_POLYMORPHIC_TYPE_HINT_BODY = '["java.util.HashMap",{"profileId":"p1"}]'
#: Deliberately not valid JSON at all (not even `{}` or the plain flat body --
#: either could legitimately succeed on one twin, which would make it a bad
#: control: it must never itself be able to produce `evidence_marker` on
#: *either* twin). Malformed input fails Jackson's parser identically for
#: both, isolating "did the type-hinted payload specifically get accepted".
_CONTROL_VALUE = "not-json-at-all"


class _SpringBootDeserializationTier12Client:
    """A minimal `Tier1Client`/`Tier2Client` adapter over
    `SpringBootLiveBootHarness`'s existing (unmodified) `post()` method.
    `param_name="body"` is this project's own established convention
    (`CC-LAB-0174`) for a whole-request-body cell with no single named
    field -- `data["body"]` here *is* the raw JSON to send, not a form field."""

    def __init__(self, harness: SpringBootLiveBootHarness) -> None:
        self._harness = harness

    def post(self, path: str, *, data: dict[str, str]):
        return self._harness.post(path, data=data["body"].encode("utf-8"), content_type="application/json")

    def fetch(self, case: Tier1Case) -> str:
        assert case.location == "body"
        return self.post(case.path, data={case.param_name: case.payload}).body


def _make_case(cell_id: str, *, expected_vulnerable: bool) -> Tier1Case:
    cell = next(c for c in load_manifest(_MANIFEST_PATH).cells if c.cell_id == cell_id)
    return build_tier1_case(
        cell, param_name="body", payload=_POLYMORPHIC_TYPE_HINT_BODY,
        evidence_marker='"status":"ok"', expected_vulnerable=expected_vulnerable,
    )


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="live-boot harness requires java + mvn on PATH and real Maven Central reachability (PA-0005)",
)
def test_jackson_deserialization_tier1_and_tier2_confirm_vulnerable_twin() -> None:
    emitter = SpringBootEmitter()
    case = _make_case("LABGEN-JV-0001", expected_vulnerable=True)
    with SpringBootLiveBootHarness(emitter, next(
        c for c in load_manifest(_MANIFEST_PATH).cells if c.cell_id == "LABGEN-JV-0001"
    )) as harness:
        client = _SpringBootDeserializationTier12Client(harness)
        tier1 = run_tier1_case(case, client)
        assert tier1.matches_expectation, (
            f"Tier 1 mismatch on the vulnerable twin: detected={tier1.vulnerable_detected}, "
            f"body={tier1.response_excerpt!r}"
        )
        oracle = LiveBootTier2Oracle(client=client, control_value=_CONTROL_VALUE)
        tier2 = run_tier2_case(case, oracle)
        assert tier2.matches_expectation, (
            f"Tier 2 mismatch on the vulnerable twin: confirmed={tier2.confirmed_vulnerable}, "
            f"detail={tier2.oracle_detail!r}"
        )


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="live-boot harness requires java + mvn on PATH and real Maven Central reachability (PA-0005)",
)
def test_jackson_deserialization_tier1_and_tier2_confirm_secure_twin() -> None:
    emitter = SpringBootEmitter()
    case = _make_case("LABGEN-JV-0002", expected_vulnerable=False)
    with SpringBootLiveBootHarness(emitter, next(
        c for c in load_manifest(_MANIFEST_PATH).cells if c.cell_id == "LABGEN-JV-0002"
    )) as harness:
        client = _SpringBootDeserializationTier12Client(harness)
        tier1 = run_tier1_case(case, client)
        assert tier1.matches_expectation, (
            f"Tier 1 mismatch on the secure twin: detected={tier1.vulnerable_detected}, "
            f"body={tier1.response_excerpt!r}"
        )
        oracle = LiveBootTier2Oracle(client=client, control_value=_CONTROL_VALUE)
        tier2 = run_tier2_case(case, oracle)
        assert tier2.matches_expectation, (
            f"Tier 2 mismatch on the secure twin: confirmed={tier2.confirmed_vulnerable}, "
            f"detail={tier2.oracle_detail!r}"
        )
