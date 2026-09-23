"""Conformance-suite pass for `go_net_http` (category 4 pilot,
`CC-LAB-0170`/`FR-LAB-76` Phase A, `CC-LAB-0172`/`FR-LAB-78` Phase B,
T-LAB0.7 Tier 3).

- Tier 0 (lint): `go vet`/`gofmt -l` on the rendered output -- owned by
  `tests/test_labgen_go_net_http.py` already; this module focuses on the
  whole-tree Tier-3 pass, matching `test_labgen_node_express_conformance.py`'s
  own split.
- Tier 3 (whole-lab regeneration): drives the real, shared
  `fuzzlab.labgen.conformance.tier3` module over `go_net_http`'s per-cell
  handler files -- the accumulator's own determinism is checked separately
  in `tests/test_labgen_go_net_http.py` since its cardinality
  (`accumulator`, fed by the whole cell set at once) does not fit the
  generic per-cell `render_whole_sample` harness.

Tiers 1/2 are not attempted here, per T-LAB0.7's own scope: they need
on-host resources this environment does not have as a matter of course
(Tier 2's live-boot proof for this stack lives in
`tests/test_labgen_go_live_boot.py`, skip-guarded on `go_boot_available()`,
not gated behind a container).
"""

from __future__ import annotations

from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.schema import load_manifest


_MANIFESTS = (
    "lab/manifests/webhook_signature_go_sample.yaml",
    "lab/manifests/ssrf_go_sample.yaml",
    "lab/manifests/access_control_go_sample.yaml",
    "lab/manifests/jwt_alg_confusion_go_sample.yaml",
)


def test_regenerate_and_diff_emitter_passes_for_every_go_net_http_sample_manifest() -> None:
    emitter = GoEmitter()
    for path in _MANIFESTS:
        manifest = load_manifest(path)
        # Should not raise -- byte-identical across two full regenerations.
        regenerate_and_diff_emitter(emitter, manifest.cells)


def test_render_whole_sample_produces_one_unique_handler_path_per_cell() -> None:
    emitter = GoEmitter()
    for path in _MANIFESTS:
        manifest = load_manifest(path)
        tree = render_whole_sample(emitter, manifest.cells)
        assert len(tree) == len(manifest.cells)
        assert all(p.startswith("labgen_go_") and p.endswith(".go") for p in tree)
