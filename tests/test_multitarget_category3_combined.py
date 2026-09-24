"""Category 3 (SaaS/productivity/collaboration) §6 step 2: run both Phase E
`TargetSpec`s (TrackerNest/`spring_boot`, `CC-LAB-0138`; Huddle Hub/
`php_laravel`, `CC-LAB-0139`) through a single
`fuzzlab.harness.multitarget.run_targets` call -- the one remaining item
both apps' own individual Phase E tests flag as "not mine to do" (see
`tests/test_labgen_spring_boot_trackernest_multitarget.py` and
`tests/test_labgen_php_laravel_huddlehub_multitarget.py`, each of which
only proves its own app's wiring in isolation), mirroring category 1's
own combined test (`tests/test_multitarget_category1_combined.py` on
`origin/claude/second-target-cat1-ecommerce`).

This closes the toolkit-side half of category 3's own Phase 10 `T10.6`-
style proof: `fuzzlab/harness/multitarget.py` actually accepting two real,
distinct, locally-booted second targets in one call and producing a real
combined `transfer_summary`. **It now claims `generalizes=True` for the
first time**: this test starts and passes a real `OobListener`
(`oob=listener`) to `run_targets` -- without one, every SSRF/XXE strategy
fails closed and never confirms, which is why an earlier version of this
test showed `generalizes=False` despite `R-SSRF`/`SsrfInBandMarkerStrategy`
(`CC-AUD-0016`/`CC-FUZZ-0031`) already existing at the time; that was this
test's own missing wiring, not a real detection gap. TrackerNest's own
recall is now 2/3 (`ssti`/`TNEST-0001` via `CC-CORE-0020`'s pre-existing
`R-SSTI`/`SstiStrategy`, and `xxe`/`TNEST-0002` via `CC-FUZZ-0035`'s new
`R-XXE`/`XxeInBandMarkerStrategy`); Huddle Hub's own recall is now 1/3
(`ssrf`/`HHUB-0002` via `R-SSRF`/`SsrfInBandMarkerStrategy`).
`webhook_signature_bypass`/`outbound_header_injection` (Huddle Hub) and
`insecure_deserialization` (TrackerNest's own real Java `ObjectInputStream`/
ysoserial-shaped binary case, a genuinely different mechanism from
Netflix's Jackson-JSON one `InsecureDeserializationTypeConfusionStrategy`
confirms) remain honestly unmapped/unconfirmed. Proving the harness can
run and combine two independent real targets from two entirely different
stacks (Java/Spring Boot and PHP/Laravel) in one pass, correctly score
each target independently, and now genuinely demonstrate cross-target
transfer (`generalizes=True`, recall > 0 on both) is the actual T10.6
toolkit-side deliverable here.

Skip-guarded on both `spring_boot_boot_available()` and
`live_boot_available()` (PA-0005/PA-0035), matching each app's own
existing live-boot test's own guard. Marked `@pytest.mark.slow` (two real
boots + real HTTP in one test).
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, format_transfer, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import SKELETON_DIR, spring_boot_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.oob import OobListener
from fuzzlab.tools.probesender import RequestsProbeSender

TRACKERNEST_GT_DIR = "lab/ground-truth-trackernest"
TRACKERNEST_MANIFESTS = (
    "lab/manifests/ssti_spring_boot_sample.yaml",
    "lab/manifests/xxe_spring_boot_sample.yaml",
    "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
)
TRACKERNEST_VULNERABLE_CELL_IDS = {"LABGEN-SSTI-0001", "LABGEN-XXE-0001", "LABGEN-DESER-0001"}

HUDDLEHUB_GT_DIR = "lab/ground-truth-huddlehub"
HUDDLEHUB_MANIFESTS = (
    "lab/manifests/webhook_signature_huddlehub_sample.yaml",
    "lab/manifests/ssrf_huddlehub_sample.yaml",
    "lab/manifests/header_injection_huddlehub_sample.yaml",
)
HUDDLEHUB_VULNERABLE_CELL_IDS = {"LABGEN-HHB-0001", "LABGEN-HHB-0003", "LABGEN-HHB-0005"}

BUILD_TIMEOUT_S = 240.0
BOOT_TIMEOUT_S = 30.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_listening(port: int, timeout_s: float = BOOT_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError as exc:
            last_exc = exc
            time.sleep(0.25)
    raise AssertionError(f"java -jar never started listening on 127.0.0.1:{port}: {last_exc}")


@pytest.fixture(scope="module")
def trackernest_app_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("trackernest_combined")
    shutil.copytree(SKELETON_DIR, root, dirs_exist_ok=True)
    emitter = SpringBootEmitter()
    cells = [c for m in TRACKERNEST_MANIFESTS for c in load_manifest(m).cells
             if c.cell_id in TRACKERNEST_VULNERABLE_CELL_IDS]
    for cell in cells:
        for f in emitter.render(cell):
            dest = root / f.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(f.content)
    return root


@pytest.fixture(scope="module")
def trackernest_base_url(trackernest_app_dir: Path):
    if not spring_boot_boot_available():
        pytest.skip("mvn/java CLI or Maven Central reachability not available (PA-0005 pattern)")
    package_result = subprocess.run(
        ["mvn", "-q", "-B", "package", "-DskipTests"],
        cwd=trackernest_app_dir, capture_output=True, text=True, timeout=BUILD_TIMEOUT_S,
    )
    assert package_result.returncode == 0, (
        f"mvn package failed:\nstdout={package_result.stdout}\nstderr={package_result.stderr}"
    )
    port = _free_port()
    jar_path = trackernest_app_dir / "target" / "trackernest.jar"
    proc = subprocess.Popen(
        ["java", "-jar", str(jar_path), f"--server.port={port}"],
        cwd=trackernest_app_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        _wait_until_listening(port)
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.mark.slow
def test_trackernest_and_huddlehub_run_together_in_one_call(trackernest_base_url, tmp_path) -> None:
    if not live_boot_available():
        pytest.skip(
            "live-boot harness requires composer + php on PATH and real Packagist "
            "network reachability (PA-0005) -- see live_boot.live_boot_available()"
        )
    huddlehub_cells = [
        c for m in HUDDLEHUB_MANIFESTS for c in load_manifest(m).cells
        if c.cell_id in HUDDLEHUB_VULNERABLE_CELL_IDS
    ]
    huddlehub_emitter = LaravelEmitter()
    trackernest_gt = contract.load(TRACKERNEST_GT_DIR)
    huddlehub_gt = contract.load(HUDDLEHUB_GT_DIR)

    listener = OobListener()
    listener.start()
    try:
        with LiveBootHarness(huddlehub_emitter, huddlehub_cells) as huddlehub_harness:
            specs = [
                TargetSpec(name="spring_boot_trackernest", base_url=trackernest_base_url,
                          ground_truth=trackernest_gt, points_source="ground-truth"),
                TargetSpec(name="php_laravel_huddlehub", base_url=huddlehub_harness._base_url(),  # noqa: SLF001
                          ground_truth=huddlehub_gt, points_source="ground-truth"),
            ]
            with Store(tmp_path / "u.db") as store:
                outcomes = run_targets(specs, store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
                                       oob=listener)
                assert [o.name for o in outcomes] == ["spring_boot_trackernest", "php_laravel_huddlehub"]
                trackernest_outcome, huddlehub_outcome = outcomes
                for outcome in outcomes:
                    assert outcome.scored is True
                    assert outcome.report is not None
                # TrackerNest: ssti (TNEST-0001, CC-CORE-0020) and xxe
                # (TNEST-0002, CC-FUZZ-0035 -- needs the real OobListener
                # above) both confirm for real; insecure_deserialization
                # (TNEST-0003, real ysoserial-shaped binary Java
                # deserialization) is a different mechanism from Netflix's
                # own confirmed Jackson-JSON case -- still unconfirmed, an
                # honest false negative, not a wiring gap. 2 of 3 positives.
                assert trackernest_outcome.report.tp == 2
                assert trackernest_outcome.report.recall == pytest.approx(2 / 3)
                # Huddle Hub: ssrf (HHUB-0002, CC-AUD-0016/CC-FUZZ-0031 --
                # also needs the real OobListener above) confirms for real;
                # webhook_signature_bypass/outbound_header_injection remain
                # unmapped -- 1 of 3 positives, not 0 as before this test
                # started passing a real listener.
                assert huddlehub_outcome.report.tp == 1
                assert huddlehub_outcome.report.recall == pytest.approx(1 / 3)
                # Two independent real run_ids, one per target, in the same call.
                assert outcomes[0].run_id != outcomes[1].run_id

                summary = transfer_summary(outcomes)
                assert summary["targets"] == 2
                assert "macro_precision" in summary and "macro_recall" in summary
                # Both scored targets now have recall > 0 -- transfer_summary's
                # own >= 2 rule is met for the first time in this combined test.
                assert summary["generalizes"] is True

                # format_transfer must not raise on a real two-target summary.
                rendered = format_transfer(summary)
                assert "spring_boot_trackernest" in rendered
                assert "php_laravel_huddlehub" in rendered
    finally:
        listener.stop()
