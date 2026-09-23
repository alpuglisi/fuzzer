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
combined `transfer_summary`. It does **not** claim `generalizes=True`:
`CC-CORE-0020` wired `ssti` into `fuzzlab.core.runmode._VULN_TO_CATEGORY`
(a pre-existing, independently-verified working rule+strategy pairing),
so TrackerNest's own recall is now 1/3 (its one `ssti` case, `TNEST-0001`,
confirms for real) -- but Huddle Hub's own three classes
(`webhook_signature_bypass`/`ssrf`/`outbound_header_injection`) and
TrackerNest's other two (`xxe`/`insecure_deserialization`) all remain
honestly unmapped (no verified confirmer built for any of them yet), so
Huddle Hub's own recall is still 0 and `generalizes` is correctly `False`
(`transfer_summary`'s own rule needs recall > 0 on **both** scored
targets to report `True`; one of two is not enough) -- this is a weaker
transfer result than category 1's own combined test (which had one real
recall>0 case from ForgeCart, also on only one of its two targets), stated
plainly rather than glossed over. Proving the harness can run and combine
two independent real targets from two entirely different stacks (Java/
Spring Boot and PHP/Laravel) in one pass, and correctly score each target
independently (one now genuinely detecting something, one not), is the
actual T10.6 toolkit-side deliverable here; a true `generalizes=True`
demonstration needs the same follow-on audit-rule wiring for the
remaining 5 classes, not a new gap introduced by this one.

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

    with LiveBootHarness(huddlehub_emitter, huddlehub_cells) as huddlehub_harness:
        specs = [
            TargetSpec(name="spring_boot_trackernest", base_url=trackernest_base_url,
                      ground_truth=trackernest_gt, points_source="ground-truth"),
            TargetSpec(name="php_laravel_huddlehub", base_url=huddlehub_harness._base_url(),  # noqa: SLF001
                      ground_truth=huddlehub_gt, points_source="ground-truth"),
        ]
        with Store(tmp_path / "u.db") as store:
            outcomes = run_targets(specs, store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
            assert [o.name for o in outcomes] == ["spring_boot_trackernest", "php_laravel_huddlehub"]
            trackernest_outcome, huddlehub_outcome = outcomes
            for outcome in outcomes:
                assert outcome.scored is True
                assert outcome.report is not None
            # TrackerNest: ssti (TNEST-0001) confirms for real (CC-CORE-0020),
            # xxe/insecure_deserialization stay unmapped -- 1 of 3 positives.
            assert trackernest_outcome.report.tp == 1
            assert trackernest_outcome.report.recall == pytest.approx(1 / 3)
            # Huddle Hub: all 3 of its own classes remain unmapped -- 0 of 3.
            assert huddlehub_outcome.report.tp == 0
            assert huddlehub_outcome.report.recall == 0.0
            # Two independent real run_ids, one per target, in the same call.
            assert outcomes[0].run_id != outcomes[1].run_id

            summary = transfer_summary(outcomes)
            assert summary["targets"] == 2
            assert "macro_precision" in summary and "macro_recall" in summary
            # Only one of the two scored targets has recall > 0 --
            # transfer_summary's own rule needs both, so generalizes is
            # still correctly False, not glossed over.
            assert summary["generalizes"] is False
            # format_transfer must not raise on a real two-target summary.
            rendered = format_transfer(summary)
            assert "spring_boot_trackernest" in rendered
            assert "php_laravel_huddlehub" in rendered
