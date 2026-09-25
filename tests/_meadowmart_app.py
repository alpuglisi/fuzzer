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
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

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
        result = subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund", "express@4.22.3"],
            cwd=probe_dir, capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def assemble(root: Path, cells=None) -> Path:
    cells = meadowmart_cells() if cells is None else cells
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
    result = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"], cwd=root, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, f"npm install failed:\n{result.stdout}\n{result.stderr}"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def boot(root: Path) -> Iterator[str]:
    """Run `node app.js` on a free loopback port; yield its base URL."""
    port = _free_port()
    proc = subprocess.Popen(
        ["node", "app.js"], cwd=root, env={**os.environ, "PORT": str(port)},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                if time.monotonic() > deadline or proc.poll() is not None:
                    raise AssertionError(f"node app.js never listened on {port}") from None
                time.sleep(0.1)
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
