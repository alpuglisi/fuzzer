"""Category 1 (E-commerce) §6 step 2: run both Phase E `TargetSpec`s
(ForgeCart/`ruby_rails`, `CC-LAB-0082`; MeadowMart BFF/`node_express`,
`CC-LAB-0079`) through a single `fuzzlab.harness.multitarget.run_targets`
call, the one remaining item both lanes' own dispatches flagged as "not
mine to do" (see `tests/test_multitarget_ruby_rails_forgecart.py` and
`tests/test_labgen_node_bff_multitarget.py`, each of which only proves its
own app's wiring in isolation).

This closes the toolkit-side half of category 1's own Phase 10 `T10.6`-style
proof: `fuzzlab/harness/multitarget.py` actually accepting two real, distinct,
locally-booted second targets in one call and producing a real combined
`transfer_summary`. It does **not** claim `generalizes=True` -- that would
require both targets to have recall > 0, and MeadowMart's two vuln classes
(`prototype_pollution`/`redos`) are honestly unmapped in
`fuzzlab.core.runmode._VULN_TO_CATEGORY` as of this test (the same
documented, flagged gap both Phase E lanes already recorded) -- ForgeCart's
real `/search` reflected-XSS confirmation is the only recall > 0 case here,
so `generalizes` is correctly `False` with exactly one scored target above
zero recall. Proving the harness can run and combine two independent real
targets in one pass is the actual T10.6 toolkit-side deliverable; a true
`generalizes=True` demonstration needs the same follow-on audit-rule wiring
both lanes already flagged, not a new gap introduced here.

Skip-guarded on both `rails_boot_available()` (PA-0005/PA-0035) and Node/npm
availability + registry reachability (PA-0005), matching each app's own
existing live-boot test's own guard. Marked `@pytest.mark.slow` (two real
boots + real HTTP in one test).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, format_transfer, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.node_express import RUNTIME_SCAFFOLD_FILES, NodeExpressEmitter
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

FORGECART_GT_DIR = "lab/ground-truth-forgecart"
FORGECART_MANIFEST = "lab/manifests/shopify_forgecart_real_pages.yaml"
MEADOWMART_GT_DIR = "lab/ground-truth-meadowmart"
PP_MANIFEST = "lab/manifests/prototype_pollution_node_sample.yaml"
RD_MANIFEST = "lab/manifests/redos_node_sample.yaml"
SCAFFOLD_DIR = Path("fuzzlab/labgen/emitters/node_express/scaffold")


def _node_available() -> bool:
    return shutil.which("node") is not None and shutil.which("npm") is not None


def _npm_registry_reachable(probe_dir: Path) -> bool:
    probe_dir.mkdir(parents=True, exist_ok=True)
    (probe_dir / "package.json").write_text(
        json.dumps({"name": "probe", "version": "1.0.0", "private": True}), encoding="utf-8"
    )
    try:
        result = subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund", "express@4.22.3"],
            cwd=probe_dir, capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_listening(port: int, timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError as exc:
            last_exc = exc
            time.sleep(0.1)
    raise AssertionError(f"node app.js never started listening on 127.0.0.1:{port}: {last_exc}")


def _boot_meadowmart(tmp_path_factory: pytest.TempPathFactory):
    """Real boot of the MeadowMart BFF app, mirroring
    `tests/test_labgen_node_bff_multitarget.py`'s own `app_dir`/
    `live_base_url` fixtures collapsed into one helper (this module needs
    both apps live at once, not as separate fixtures pytest could tear down
    out of order relative to the Rails harness's own context manager)."""
    root = tmp_path_factory.mktemp("meadowmart_bff_combined")
    (root / "routes").mkdir()
    for name in RUNTIME_SCAFFOLD_FILES:  # CC-LAB-0246 R7
        (root / name).write_bytes((SCAFFOLD_DIR / name).read_bytes())

    emitter = NodeExpressEmitter()
    cells = [*load_manifest(PP_MANIFEST).cells, *load_manifest(RD_MANIFEST).cells]
    for cell in cells:
        for f in emitter.render(cell):
            (root / f.path).write_bytes(f.content)
    accumulator = emitter.render_route_accumulator(cells)
    (root / accumulator.path).write_bytes(accumulator.content)

    result = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"],
        cwd=root, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, f"npm install failed:\nstdout={result.stdout}\nstderr={result.stderr}"

    port = _free_port()
    proc = subprocess.Popen(
        ["node", "app.js"], cwd=root, env={**os.environ, "PORT": str(port)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    _wait_until_listening(port)
    return proc, f"http://127.0.0.1:{port}"


@pytest.mark.slow
@pytest.mark.skipif(
    not rails_boot_available(),
    reason="rails live-boot harness requires ruby + bundle on PATH and real RubyGems reachability (PA-0005/PA-0035)",
)
def test_run_targets_combines_forgecart_and_meadowmart_in_one_call(tmp_path_factory: pytest.TempPathFactory) -> None:
    if not _node_available():
        pytest.skip("node/npm CLI not available on this build host (PA-0005 pattern)")
    if not _npm_registry_reachable(tmp_path_factory.mktemp("npm_probe")):
        pytest.skip("npm registry not reachable from this sandbox")

    rails_manifest = load_manifest(FORGECART_MANIFEST)
    rails_emitter = RailsEmitter()
    node_proc = None
    try:
        with RailsLiveBootHarness(rails_emitter, rails_manifest.cells) as rails_harness:
            node_proc, node_base_url = _boot_meadowmart(tmp_path_factory)

            forgecart_gt = contract.load(FORGECART_GT_DIR)
            meadowmart_gt = contract.load(MEADOWMART_GT_DIR)
            specs = [
                TargetSpec(
                    name="ruby_rails_forgecart", base_url=rails_harness._base_url(),
                    ground_truth=forgecart_gt, points_source="ground-truth",
                ),
                TargetSpec(
                    name="node_express_meadowmart_bff", base_url=node_base_url,
                    ground_truth=meadowmart_gt, points_source="ground-truth",
                ),
            ]

            with Store(":memory:") as store:
                outcomes = run_targets(
                    specs, store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
                )

            assert [o.name for o in outcomes] == ["ruby_rails_forgecart", "node_express_meadowmart_bff"]
            forgecart_outcome, meadowmart_outcome = outcomes

            # Both targets ran and were scored for real, independently -- the
            # actual T10.6 toolkit-side deliverable (two real, distinct
            # second targets, one harness call).
            assert forgecart_outcome.scored and forgecart_outcome.report is not None
            assert meadowmart_outcome.scored and meadowmart_outcome.report is not None
            assert forgecart_outcome.run_id != meadowmart_outcome.run_id

            # ForgeCart's own real /search reflected-XSS confirmation still
            # holds when run alongside a second target, not just in
            # isolation (guards against one target's boot/state leaking
            # into the other's run).
            assert forgecart_outcome.report.tp >= 1, (
                f"expected ForgeCart's real /search XSS case confirmed "
                f"even when run combined with MeadowMart; report={forgecart_outcome.report.as_dict()}"
            )
            # MeadowMart's honestly-0 recall (documented gap: prototype_pollution/
            # redos aren't yet mapped into fuzzlab.core.runmode._VULN_TO_CATEGORY)
            # holds unchanged in the combined run too.
            assert meadowmart_outcome.report.tp == 0

            summary = transfer_summary(outcomes)
            assert summary["targets"] == 2
            assert "ruby_rails_forgecart" in summary["found_on"]
            # generalizes requires >= 2 scored targets each with recall > 0;
            # only ForgeCart has one here, so this is correctly False, not
            # papered over -- the real follow-on (wiring MeadowMart's own
            # vuln classes into the audit/category-mapping layer) is out of
            # this test's scope, exactly as both Phase E lanes flagged.
            assert summary["generalizes"] is False
            text = format_transfer(summary)
            assert "ruby_rails_forgecart: tp=" in text
            assert "node_express_meadowmart_bff: tp=" in text
    finally:
        if node_proc is not None:
            node_proc.terminate()
            try:
                node_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                node_proc.kill()
                node_proc.wait(timeout=5)
