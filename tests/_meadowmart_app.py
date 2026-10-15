"""Shared helper: assemble, install and boot the MeadowMart BFF app for real
(CC-LAB-0246, `docs/LAB_LANE6_NODE_FASTAPI_PLAN.md` §2A-e). Mirrors Lane 2's
`tests/_django_site.py`: one place that knows how the app tree is built, so
the navigability module does not grow yet another copy of the fixture logic
the older MeadowMart modules each carry.

The app is exactly MeadowMart's own build (`MEADOWMART_MANIFESTS`), the
scaffold files a running app needs (`RUNTIME_SCAFFOLD_FILES`), every cell's
controller, and the route accumulator (`app.js`). Skip-guarded (PA-0005 /
PA-0035) on `node`/`npm` and on a real, bounded `npm install` probe.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from fuzzlab import procutil
from fuzzlab.labgen.emitters.node_express import (
    MEADOWMART_MANIFESTS,
    RUNTIME_SCAFFOLD_FILES,
    NodeExpressEmitter,
)
from fuzzlab.labgen.schema import load_manifest

SCAFFOLD_DIR = Path("fuzzlab/labgen/emitters/node_express/scaffold")


def meadowmart_cells():
    return [c for m in MEADOWMART_MANIFESTS for c in load_manifest(m).cells]


def node_available() -> bool:
    return shutil.which("node") is not None and shutil.which("npm") is not None


def npm_registry_reachable(probe_dir: Path) -> bool:
    probe_dir.mkdir(parents=True, exist_ok=True)
    (probe_dir / "package.json").write_text(
        json.dumps({"name": "probe", "version": "1.0.0", "private": True}), encoding="utf-8"
    )
    try:
        result = procutil.run_bounded(
            ["npm", "install", "--no-audit", "--no-fund", "express@4.22.3"],
            cwd=probe_dir, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def assemble(root: Path, cells=None) -> Path:
    if cells is None:
        # CC-LAB-0247 (Lane 7, Gate D, PA-0027): the default (every real
        # cell) case delegates to the shared `assemble_meadowmart_app`, the
        # same assembly `lab/web-node.Dockerfile`'s own `gen` stage uses --
        # one source, not two independently-maintained copies.
        from fuzzlab.labgen.emitters.node_express import assemble_meadowmart_app

        assemble_meadowmart_app(str(root))
        return root
    (root / "routes").mkdir(parents=True, exist_ok=True)
    for name in RUNTIME_SCAFFOLD_FILES:
        (root / name).write_bytes((SCAFFOLD_DIR / name).read_bytes())
    emitter = NodeExpressEmitter()
    for cell in cells:
        for f in emitter.render(cell):
            (root / f.path).write_bytes(f.content)
    acc = emitter.render_route_accumulator(cells)
    (root / acc.path).write_bytes(acc.content)
    return root


def install(root: Path, probe_dir: Path) -> None:
    if not node_available():
        pytest.skip("node/npm CLI not available on this build host (PA-0005 pattern)")
    if not npm_registry_reachable(probe_dir):
        pytest.skip("npm registry not reachable from this sandbox")
    result = procutil.run_bounded(
        ["npm", "install", "--no-audit", "--no-fund"], cwd=root, timeout=120,
    )
    assert result.returncode == 0, f"npm install failed:\n{result.stdout}\n{result.stderr}"


@contextlib.contextmanager
def boot(root: Path) -> Iterator[str]:
    """Run `node app.js` on a free loopback port; yield its base URL."""
    server, port = procutil.start_server_on_free_port(  # BUG-0143: our own listener
        lambda port: ["node", "app.js"], boot_timeout=15.0, cwd=root,
        env_for=lambda port: {**os.environ, "PORT": str(port), "HOST": "127.0.0.1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        procutil.assert_loopback_only(server)  # BUG-0130: checked after boot
        yield f"http://127.0.0.1:{port}"
    finally:
        procutil.stop_server(server)
