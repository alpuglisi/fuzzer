"""Phase E: wire TrackerNest (`spring_boot`, category 3's Atlassian pick)
into `fuzzlab.harness.multitarget` as its own real `TargetSpec`
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6/§9.4, `CC-LAB-0138`).

Runs the real thing end to end: a real `mvn package` + `java -jar` boot of
the whole assembled app (all three of TrackerNest's vulnerable cells at
once, on their three distinct routes), a real
`fuzzlab.tools.probesender.RequestsProbeSender` sending real HTTP over the
loopback socket, and `fuzzlab.harness.multitarget.run_targets`/
`transfer_summary` run against it for real.

**Why this test assembles the app by hand rather than reusing
`SpringBootLiveBootHarness`.** That harness deliberately takes exactly one
cell (its own docstring: "a same-route twin pair would collide if booted
together") -- a real, correct restriction for *its* job (proving one
cell's vulnerable-vs-secure differential), but TrackerNest's three cells
each live on their own distinct route (`/wiki/pages/render`,
`/issues/import`, `/integrations/webhook-payload`), so booting all three
*vulnerable* twins together (never the secure ones alongside them, which
would still collide) is both real-bootable and exactly what Phase C's own
ground truth (`lab/ground-truth-trackernest/`, `CC-LAB-0136`) describes as
"the app." This mirrors category 1's own Phase E precedent
(`tests/test_labgen_node_bff_multitarget.py` on
`origin/claude/second-target-cat1-ecommerce`), which hand-rolled its own
assembly/boot fixture for the identical reason rather than fighting a
conformance harness's own single-purpose restriction.

**Recall is honestly 0 here, and that is expected, not a bug** -- same
documented gap as category 1's own Phase E tests: none of `ssti`/`xxe`/
`insecure_deserialization` are mapped by
`fuzzlab.core.runmode._VULN_TO_CATEGORY`, so no audit rule ever gets a
candidate to confirm. Wiring that mapping is real, sized follow-on work
this test does not attempt -- its job is to prove the wiring (a real
target, a real ground truth, a real run, a real scored report).

Skip-guarded on `spring_boot_boot_available()` (PA-0005/PA-0035, the same
real, bounded Maven-network capability probe every other `spring_boot`
live-boot test in this project already uses). Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.live_boot_spring_boot import SKELETON_DIR, spring_boot_boot_available
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

GT_DIR = "lab/ground-truth-trackernest"
MANIFESTS = (
    "lab/manifests/ssti_spring_boot_sample.yaml",
    "lab/manifests/xxe_spring_boot_sample.yaml",
    "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
)
#: Only the vulnerable half of each same-route twin pair -- the secure
#: twin sharing that same route would still collide (see this module's own
#: docstring); ground truth (`CC-LAB-0136`) describes exactly this
#: three-cell, all-vulnerable deployment.
VULNERABLE_CELL_IDS = {"LABGEN-SSTI-0001", "LABGEN-XXE-0001", "LABGEN-DESER-0001"}
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
def app_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("trackernest_multitarget")
    shutil.copytree(SKELETON_DIR, root, dirs_exist_ok=True)

    emitter = SpringBootEmitter()
    cells = [c for m in MANIFESTS for c in load_manifest(m).cells if c.cell_id in VULNERABLE_CELL_IDS]
    assert {c.cell_id for c in cells} == VULNERABLE_CELL_IDS
    for cell in cells:
        for f in emitter.render(cell):
            dest = root / f.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(f.content)
    return root


@pytest.fixture(scope="module")
def live_base_url(app_dir: Path):
    if not spring_boot_boot_available():
        pytest.skip("mvn/java CLI or Maven Central reachability not available (PA-0005 pattern)")
    package_result = subprocess.run(
        ["mvn", "-q", "-B", "package", "-DskipTests"],
        cwd=app_dir, capture_output=True, text=True, timeout=BUILD_TIMEOUT_S,
    )
    assert package_result.returncode == 0, (
        f"mvn package failed:\nstdout={package_result.stdout}\nstderr={package_result.stderr}"
    )

    port = _free_port()
    jar_path = app_dir / "target" / "trackernest.jar"
    proc = subprocess.Popen(
        ["java", "-jar", str(jar_path), f"--server.port={port}"],
        cwd=app_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
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
def test_trackernest_target_spec_runs_for_real_and_scores(live_base_url, tmp_path) -> None:
    gt = contract.load(GT_DIR)
    spec = TargetSpec(
        name="spring_boot_trackernest", base_url=live_base_url,
        ground_truth=gt, points_source="ground-truth",
    )
    with Store(tmp_path / "u.db") as store:
        outcomes = run_targets([spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
        assert [o.name for o in outcomes] == ["spring_boot_trackernest"]
        outcome = outcomes[0]
        # Real target, real ground truth -> a real, scored report (D14: automatic
        # mode + ground truth is always scored, regardless of tp count).
        assert outcome.scored is True
        assert outcome.report is not None
        assert outcome.report.tp == 0 and outcome.report.fn == len(gt.positives())
        assert outcome.report.precision == 0.0
        assert outcome.report.recall == 0.0

        summary = transfer_summary(outcomes)
        assert summary["targets"] == 1
        assert "macro_precision" in summary and "macro_recall" in summary
        assert summary["generalizes"] is False


@pytest.mark.slow
def test_trackernest_endpoints_are_really_live(live_base_url) -> None:
    """Confirms the booted app is genuinely the real TrackerNest build (not
    an empty skeleton the `run_targets` call above merely failed to reach) --
    a real, distinguishable response from each of the three vulnerable
    cells' own routes."""
    import requests

    r1 = requests.get(f"{live_base_url}/wiki/pages/render", params={"macroExpr": "7"}, timeout=10)
    assert r1.status_code == 200
    assert "Rendered macro result" in r1.text

    r2 = requests.post(
        f"{live_base_url}/issues/import",
        data="<issue><title>hello</title></issue>".encode("utf-8"),
        headers={"Content-Type": "application/xml"}, timeout=10,
    )
    assert r2.status_code == 200
    assert "Imported issue title: hello" in r2.text

    # Third cell's own route: a non-exploit request (garbage bytes, not a
    # real serialized object) still proves the deserialization controller
    # is genuinely mounted in *this* 3-cell-combined deployment specifically
    # -- not merely that its sink code works in isolation (already proven
    # separately by CC-LAB-0132's own live-boot test) -- a real 400 from
    # `ObjectInputStream.readObject()` failing on non-serialized bytes,
    # never a 404/501 that would mean the route never registered at all.
    r3 = requests.post(
        f"{live_base_url}/integrations/webhook-payload",
        data=b"not a real serialized object",
        headers={"Content-Type": "application/octet-stream"}, timeout=10,
    )
    assert r3.status_code == 400
    assert "Webhook payload error" in r3.text
