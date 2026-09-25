"""Phase E: wire the MeadowMart BFF (`node_express`, CC-LAB-0077) into
`fuzzlab.harness.multitarget` as its own real `TargetSpec`
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6/§9.4a/§9.5, this app's
half only -- the concurrent Rails/Shopify lane owns its own `TargetSpec`).

Unlike `tests/test_multitarget.py` (which proves the harness plumbing with a
hand-written fake `AutoSender`), this module runs the real thing end to end:
a real `npm install` + `node app.js` boot of the whole assembled app (same
fixture shape as `tests/test_labgen_node_bff_app.py`), a real
`fuzzlab.tools.probesender.RequestsProbeSender` sending real HTTP over the
loopback socket, and `fuzzlab.harness.multitarget.run_targets`/
`transfer_summary` run against it for real -- proving `run_auto`'s ground-
truth-sourced flow actually executes against a real, locally-booted second
target and produces a real per-target `ScoreReport`, not just a fake-sender
simulation of the plumbing.

**Recall is honestly 0 here, and that is expected, not a bug**: the ground
truth's `vuln_class` values (`prototype_pollution`/`redos`) are not mapped
by `fuzzlab.core.runmode._VULN_TO_CATEGORY`, so `resolve_run`'s
ground-truth-derived category set is the raw class names themselves --
neither of which is a category `fuzzlab.audit.rules.known_categories()`
carries a rule for (`sql-injection`/`xss`/`command-injection`/etc. only), so
`evaluate()` nominates zero candidates for either and the pipeline's own
"no confirmer for this category yet" branch (`fuzzlab.harness.pipeline.
run_pipeline`) never even gets a candidate to skip. (A downstream
confirmation strategy for ReDoS does exist -- `RegexDosStrategy`,
`vuln_class="redos"`/`category="regular-expression"` -- but nothing
upstream of it currently produces a candidate under either category string;
wiring an audit rule and the `_VULN_TO_CATEGORY` mapping for these two
classes is real, sized follow-on work this pass does not attempt.) This is
the same documented, flagged-gap discipline `points_from_ground_truth`
already uses for DOM/stored-XSS points needing a browser. This test's job
is to prove the *wiring* (a real target, a real ground truth, a real run, a
real scored report), not to build that follow-on detection wiring, which is
out of this task's scope.
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
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.emitters.node_express import RUNTIME_SCAFFOLD_FILES, NodeExpressEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.probesender import RequestsProbeSender

PP_MANIFEST = "lab/manifests/prototype_pollution_node_sample.yaml"
RD_MANIFEST = "lab/manifests/redos_node_sample.yaml"
SCAFFOLD_DIR = Path("fuzzlab/labgen/emitters/node_express/scaffold")
GT_DIR = "lab/ground-truth-meadowmart"


def node_available() -> bool:
    return shutil.which("node") is not None and shutil.which("npm") is not None


def _npm_registry_reachable(probe_dir: Path) -> bool:
    """See `tests/test_labgen_node_bff_app.py`'s identical helper's docstring
    for why `probe_dir` must be a dedicated, not-yet-existing temp directory,
    never one derived from another fixture's `tmp_path_factory` result's
    parent."""
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


@pytest.fixture(scope="module")
def app_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("meadowmart_bff_multitarget")
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
    return root


@pytest.fixture(scope="module")
def live_base_url(app_dir: Path, tmp_path_factory: pytest.TempPathFactory):
    if not node_available():
        pytest.skip("node/npm CLI not available on this build host (PA-0005 pattern)")
    if not _npm_registry_reachable(tmp_path_factory.mktemp("npm_probe")):
        pytest.skip("npm registry not reachable from this sandbox")
    result = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"],
        cwd=app_dir, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, f"npm install failed:\nstdout={result.stdout}\nstderr={result.stderr}"

    port = _free_port()
    proc = subprocess.Popen(
        ["node", "app.js"], cwd=app_dir, env={**os.environ, "PORT": str(port)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
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


def test_meadowmart_bff_target_spec_runs_for_real_and_scores(live_base_url, tmp_path) -> None:
    gt = contract.load(GT_DIR)
    spec = TargetSpec(
        name="node_express_meadowmart_bff",
        base_url=live_base_url,
        ground_truth=gt,
        points_source="ground-truth",
    )
    with Store(tmp_path / "u.db") as store:
        outcomes = run_targets(
            [spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
        )
        assert [o.name for o in outcomes] == ["node_express_meadowmart_bff"]
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
        # A single target with recall==0 cannot itself demonstrate
        # generalization (>= 2 scored targets each with recall > 0, per
        # transfer_summary's own rule) -- correctly reported as such, not
        # papered over.
        assert summary["generalizes"] is False


def test_multiple_runs_against_the_same_live_target_get_distinct_run_ids(live_base_url, tmp_path) -> None:
    """`run_targets` can be invoked more than once against the same real,
    already-booted target (e.g. a follow-on run alongside the Rails/Shopify
    target once both are combined, per §6 step 2) without reusing a run_id."""
    gt = contract.load(GT_DIR)
    specs = [
        TargetSpec(name="node_express_meadowmart_bff", base_url=live_base_url,
                  ground_truth=gt, points_source="ground-truth"),
    ]
    with Store(tmp_path / "u.db") as store:
        first = run_targets(specs, store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
        second = run_targets(specs, store, sender_for=lambda s: RequestsProbeSender(timeout=10.0))
        assert first[0].run_id != second[0].run_id
