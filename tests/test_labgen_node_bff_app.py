"""Whole-app live-boot proof for the MeadowMart BFF (`node_express`), CC-LAB-0077/
FR-LAB-81 (Phase C/D of `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4a/§9.5's
Category 1 (E-commerce) Walmart/Node pilot).

Everything prior to this file proved the two real cells' vulnerable/secure
mechanism in isolation: each controller module `require()`'d directly and driven
with a fake `req`/`res` (`tests/test_labgen_prototype_pollution.py`,
`tests/test_labgen_redos.py`). That is real proof of the *mechanism*, but never
proved that:

1. Both cells' routes, PLUS this app's surrounding inert pages, actually coexist
   and boot together in **one** running Express process assembled by
   `NodeExpressEmitter.render_route_accumulator` over the app's full cell set
   (the accumulator's real cardinality -- fed by every cell at once -- per that
   module's own docstring). A per-cell isolation test structurally cannot catch a
   route-registration collision or a boot-time failure that only shows up once
   every cell's controller is required into the same `app.js`.
2. The vulnerable/secure differential still holds when driven over a real TCP/HTTP
   round trip against that live process, not just a direct in-process function
   call.

This module does both, for real: a real `npm install` (network-reachable in this
sandbox, confirmed at authoring time -- both `express` and `mysql2` install in a
couple of seconds against the real npm registry through this environment's
configured proxy), a real `node app.js` subprocess bound to 127.0.0.1, and real
HTTP requests via `urllib.request` against it.

Skip-guarded (PA-0005's pattern) when `node`/`npm` are not on the build host, or
when `npm install` cannot reach the registry (offline sandbox) -- the exact same
discipline `tests/test_labgen_prototype_pollution.py`/`test_labgen_redos.py`
already use for `node` itself, extended to `npm`'s network dependency.

**A caveat stated plainly, not glossed over:** the prototype-pollution finding is,
by its real nature, invisible in the polluting request's own HTTP response (see
`test_labgen_prototype_pollution.py`'s own comment on this) -- polluting
`Object.prototype` has no in-band HTTP signal on its own; real-world detection of
it typically needs a second, downstream "gadget" request that happens to consult
the polluted property, which this app does not have and this pass does not add
(out of scope -- flagged, not silently assumed away). This module's real-HTTP
proof for that cell is therefore necessarily narrower than the ReDoS cell's (which
*does* have a directly observable real-HTTP timing signal): it proves the whole
app boots with that route live and correctly merging ordinary payloads over real
HTTP, and leaves the actual pollution differential to the already-real,
already-executed-Node-subprocess proof in `test_labgen_prototype_pollution.py`
(same mechanism, now additionally confirmed reachable at its real, coherent
`/api/preferences` URL inside the fully assembled app -- see
`test_the_two_real_pages_are_served_at_their_coherent_bff_urls` below).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from fuzzlab.labgen.emitters.node_express import NodeExpressEmitter
from fuzzlab.labgen.schema import load_manifest

PP_MANIFEST = "lab/manifests/prototype_pollution_node_sample.yaml"
RD_MANIFEST = "lab/manifests/redos_node_sample.yaml"
SCAFFOLD_DIR = Path("fuzzlab/labgen/emitters/node_express/scaffold")

_EVIL_TERM = "(a+)+$"
_BENIGN_TERM = "shoes"
# Wide margin over an HTTP round trip (loopback + Express + Node request
# parsing all add a few ms of their own, on top of the ~55-70ms in-process
# figure `test_labgen_redos.py` measured) -- see that module's own comment on
# why the margin is deliberately wide on both sides.
_VULNERABLE_FLOOR_MS = 20.0
_SECURE_CEILING_MS = 40.0


def node_available() -> bool:
    return shutil.which("node") is not None and shutil.which("npm") is not None


def _npm_registry_reachable(probe_dir: Path) -> bool:
    """A real, bounded `npm install` of a tiny real package, exercising the
    actual operation path (PA-0035's rule: never a bare socket/DNS stand-in
    for the real check). ``probe_dir`` must not yet exist -- callers pass a
    fresh, dedicated temp directory (not a shared parent: `pytest`'s
    `tmp_path_factory.mktemp()` results across DIFFERENT test modules share
    one session-level base temp dir as their common parent, so a fixed-name
    probe directory derived from `app_dir.parent` collides across modules
    when both run in the same session)."""
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


def _http_raw(method: str, port: int, path: str, body: dict | None = None) -> tuple[int, bytes, float]:
    """A real HTTP round trip (urllib, no mocking) -- returns (status, raw_body, elapsed_ms)."""
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return status, raw, elapsed_ms


def _http(method: str, port: int, path: str, body: dict | None = None) -> tuple[int, dict, float]:
    """Same as `_http_raw`, JSON-decoded -- for the JSON-responding routes
    (the inert pages and `/api/preferences`'s two twins)."""
    status, raw, elapsed_ms = _http_raw(method, port, path, body)
    return status, json.loads(raw.decode("utf-8")), elapsed_ms


def _http_text(method: str, port: int, path: str) -> tuple[int, str, float]:
    """Same as `_http_raw`, decoded as plain text -- for `/api/search`'s two
    twins, which `res.send()` a plain string, not JSON (see
    `templates/sinks/regex_highlight_match.js.j2`)."""
    status, raw, elapsed_ms = _http_raw(method, port, path)
    return status, raw.decode("utf-8"), elapsed_ms


@pytest.fixture(scope="module")
def app_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Assemble the whole MeadowMart BFF app tree for real: the scaffold's
    package.json/db.js, every supported cell's controller (rendered by
    `NodeExpressEmitter.render`), and the route accumulator (`app.js`, built
    once over the app's **full** cell set -- both real manifests together, per
    `render_route_accumulator`'s documented cardinality)."""
    root = tmp_path_factory.mktemp("meadowmart_bff_app")
    (root / "routes").mkdir()

    for name in ("package.json", "db.js"):
        (root / name).write_bytes((SCAFFOLD_DIR / name).read_bytes())

    emitter = NodeExpressEmitter()
    cells = [*load_manifest(PP_MANIFEST).cells, *load_manifest(RD_MANIFEST).cells]
    assert {c.cell_id for c in cells} == {
        "LABGEN-PP-0001", "LABGEN-PP-0002", "LABGEN-RD-0001", "LABGEN-RD-0002",
    }

    for cell in cells:
        files = emitter.render(cell)
        for f in files:
            (root / f.path).write_bytes(f.content)

    accumulator = emitter.render_route_accumulator(cells)
    (root / accumulator.path).write_bytes(accumulator.content)
    return root


@pytest.fixture(scope="module")
def npm_installed(app_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not node_available():
        pytest.skip("node/npm CLI not available on this build host (PA-0005 pattern)")
    if not _npm_registry_reachable(tmp_path_factory.mktemp("npm_probe")):
        pytest.skip("npm registry not reachable from this sandbox")
    result = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"],
        cwd=app_dir, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, f"npm install failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    return app_dir


@pytest.fixture(scope="module")
def live_app(npm_installed: Path):
    """Boot the whole assembled app for real (`node app.js`), yield its
    base port, and terminate it on teardown."""
    port = _free_port()
    proc = subprocess.Popen(
        ["node", "app.js"],
        cwd=npm_installed,
        env={**os.environ, "PORT": str(port)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        _wait_until_listening(port)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Whole-app boot: every route registered together actually answers over real
# HTTP -- the surrounding inert pages, and both real pages' canonical URLs.
# ---------------------------------------------------------------------------


def test_inert_surrounding_pages_answer_over_real_http(live_app) -> None:
    port = live_app
    status, body, _ = _http("GET", port, "/api/products")
    assert status == 200 and "products" in body and len(body["products"]) >= 1

    status, body, _ = _http("GET", port, "/api/orders/ORD-12345")
    assert status == 200 and body.get("status") == "in_transit" and body.get("history")

    status, body, _ = _http("GET", port, "/api/cart")
    assert status == 200 and "items" in body and "total" in body


def test_the_two_real_pages_are_served_at_their_coherent_bff_urls(live_app) -> None:
    """CC-LAB-0077: the canonical (vulnerable) cell of each real-page pair is
    served at the actual BFF URL a fuzzer would plausibly find
    (`/api/preferences`, `/api/search`), not a synthetic `/generated/...`
    one -- the coherent-app-identity requirement made concrete and checked
    over real HTTP against the fully assembled app."""
    port = live_app
    status, body, _ = _http("POST", port, "/api/preferences", {"theme": "dark"})
    assert status == 200 and body == {"preferences": {"theme": "dark", "notifications": True}}

    status, text, _ = _http_text("GET", port, "/api/search?q=shoes")
    assert status == 200 and "Comfortable running" in text and "<mark>shoes</mark>" in text


def test_the_secure_twins_are_reachable_at_their_own_twin_urls(live_app) -> None:
    port = live_app
    status, body, _ = _http(
        "POST", port, "/api/preferences-twin-labgen-pp-0002", {"theme": "dark"}
    )
    assert status == 200 and body == {"preferences": {"theme": "dark", "notifications": True}}

    status, _, _ = _http_text("GET", port, "/api/search-twin-labgen-rd-0002?q=shoes")
    assert status == 200


# ---------------------------------------------------------------------------
# The real payload differential over real HTTP, driven at the fully assembled
# app -- ReDoS has a directly observable real-HTTP timing signal; see the
# module docstring for why prototype pollution's own real-HTTP proof here is
# necessarily the ordinary-payload round trip, not the pollution itself.
# ---------------------------------------------------------------------------


def test_vulnerable_search_route_is_slow_on_the_evil_pattern_over_real_http(live_app) -> None:
    port = live_app
    benign_status, _, benign_ms = _http_text("GET", port, f"/api/search?q={urllib.parse.quote(_BENIGN_TERM)}")
    evil_status, _, evil_ms = _http_text("GET", port, f"/api/search?q={urllib.parse.quote(_EVIL_TERM)}")
    assert benign_status == 200 and evil_status == 200
    assert evil_ms > _VULNERABLE_FLOOR_MS, (
        f"vulnerable /api/search did not show the expected catastrophic-backtracking "
        f"slowdown over real HTTP: benign={benign_ms:.2f}ms evil={evil_ms:.2f}ms"
    )


def test_secure_search_twin_stays_fast_on_the_evil_pattern_over_real_http(live_app) -> None:
    port = live_app
    evil_status, _, evil_ms = _http_text(
        "GET", port, f"/api/search-twin-labgen-rd-0002?q={urllib.parse.quote(_EVIL_TERM)}"
    )
    assert evil_status == 200
    assert evil_ms < _SECURE_CEILING_MS, (
        f"secure search twin was unexpectedly slow on the evil pattern over real HTTP: "
        f"evil={evil_ms:.2f}ms"
    )


def test_both_preference_routes_still_merge_ordinary_keys_correctly_over_real_http(live_app) -> None:
    """Neither twin is a "reject everything" stub -- an ordinary preferences
    update round-trips correctly at both the canonical and twin URL, over a
    real HTTP request against the fully assembled, live-booted app."""
    port = live_app
    for path in ("/api/preferences", "/api/preferences-twin-labgen-pp-0002"):
        status, body, _ = _http("POST", port, path, {"notifications": False})
        assert status == 200
        assert body == {"preferences": {"theme": "light", "notifications": False}}, path
