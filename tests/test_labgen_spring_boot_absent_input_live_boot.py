"""PA-0053/PA-0054/PA-0056 own-method bare-request sweep for every
`spring_boot` route (CC-LAB-0244 / FR-LAB-165,
`docs/LAB_LANE4_SPRING_BOOT_PLAN.md` §2e/§4 step 6, BUG-0054).

Boots every `spring_boot` **vulnerable** cell together as one Spring app and
every **secure** cell together as a second one. The 16 routes are pairwise
distinct within each group, so neither build hits the same-route twin
collision (plan S1). This module is independent of the new site layer (it
uses the emitter's default, single-cell URLs), so the identical test could
be run against the pre-fix emitter to capture BUG-0054's "before" evidence
(plan §5 step 2).

For each route it sends:

* a **bare request with the route's own method** -- no query, no headers,
  and for a POST an empty body. PA-0054's original sweep was a bare `GET`,
  which a POST-only route answers with Spring's own 405 before any source
  runs, so it never saw the two POST crashes this module was written to
  catch (plan S5);
* a bare `GET`.

It asserts the own-method status equals the **declared** absent-input status
of plan §2e on both twins (not merely `< 500`), and that no bare `GET`
answers `>= 500`. :data:`EXPECTED_BARE_STATUS` is that contract, restated
here on purpose; `tests/test_labgen_spring_boot_browsable.py`
cross-checks it offline against the emitter's own `absent_input`
declarations.

Skip-guarded (PA-0005) on `spring_boot_boot_available()` and marked `slow`.
"""

from __future__ import annotations

import glob
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    _NO_REDIRECT_OPENER,
    SKELETON_DIR,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not spring_boot_boot_available(),
        reason=(
            "spring_boot live-boot harness requires java + mvn on PATH and real Maven Central "
            "reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
        ),
    ),
]

#: The plan §2e contract: route -> the status a bare request with the
#: route's **own method** gets, on both twins.
EXPECTED_BARE_STATUS: dict[str, int] = {
    # GET routes
    "/wiki/pages/render": 200,  # form_when_absent: the page, form only, sink not run
    "/api/support/template-preview": 400,  # required_param
    "/api/hotels/search-sort": 200,  # default_value 'recommended'
    "/api/account/billing": 400,  # required_param
    "/api/account/preferences": 401,  # required_header
    # POST routes
    "/issues/import": 400,  # empty_body_400
    "/integrations/webhook-payload": 400,  # empty_body_400
    "/api/playback/resume": 400,  # empty_body_400
    "/api/profiles/switch": 400,  # empty_body_400
    "/api/content/import": 400,  # empty_body_400
    "/api/subscription/change-plan": 400,  # empty_body_400
    "/api/account/settings": 400,  # empty_body_400
    "/api/trips/restore": 400,  # empty_body_400
    "/api/profiles/avatar": 400,  # required_multipart
    "/api/content/thumbnail-import": 400,  # required_param
    "/api/session/refresh": 200,  # no_input
}

#: The vulnerable op of every twin pair (the other twin is the secure one).
_VULNERABLE_OPS = frozenset({
    "user_supplied_template_compile", "xml_external_entities_enabled", "function_executing_deserialize",
    "jackson_default_typing_deserialize", "standard_evaluation_context_unrestricted", "no_ownership_check",
    "client_trusted_amount", "no_extension_check", "unfiltered_object_assign", "jwt_alg_none_default",
    "unchecked_url_fetch", "predictable_token_source",
})

BUILD_TIMEOUT_S = 400.0
BOOT_TIMEOUT_S = 60.0


def _spring_cells():
    emitter = SpringBootEmitter()
    seen = {}
    for path in sorted(glob.glob("lab/manifests/*.yaml")):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "spring_boot" and emitter.supports(cell.vuln_class, cell.sink_context):
                seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


def _request(base: str, method: str, path: str, data: bytes | None = None) -> int:
    req = urllib.request.Request(base + path, method=method, data=data)
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=20) as resp:
            return resp.status
    except Exception:  # noqa: BLE001 -- a dropped connection counts as a failure (status 0)
        return 0


@pytest.fixture(scope="module", params=["vulnerable", "secure"])
def booted_group(request, tmp_path_factory):
    label = request.param
    cells = [c for c in _spring_cells() if (c.transform.ops[0] in _VULNERABLE_OPS) == (label == "vulnerable")]
    routes = [c.route.path for c in cells]
    assert len(routes) == len(set(routes)) == 16, sorted(routes)
    tmp = Path(tempfile.mkdtemp(prefix=f"fuzzlab-spring-absent-{label}-"))
    app = tmp / "app"
    shutil.copytree(SKELETON_DIR, app)
    emitter = SpringBootEmitter()
    for cell in cells:
        for emitted in emitter.render(cell):
            dest = app / emitted.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(emitted.content)
    proc = None
    try:
        built = subprocess.run(["mvn", "-q", "-B", "package", "-DskipTests"], cwd=app,
                               capture_output=True, text=True, timeout=BUILD_TIMEOUT_S)
        assert built.returncode == 0, built.stdout[-4000:] + built.stderr[-4000:]
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        proc = subprocess.Popen(["java", "-jar", "target/trackernest.jar", f"--server.port={port}"],
                                cwd=app, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                assert time.monotonic() < deadline, "app did not boot"
                time.sleep(0.25)
        yield label, cells, f"http://127.0.0.1:{port}"
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def test_every_route_declares_a_bare_status_in_this_contract() -> None:
    """Non-vacuous guard: the contract covers exactly the 16 served routes."""
    assert set(EXPECTED_BARE_STATUS) == {c.route.path for c in _spring_cells()}


def test_bare_own_method_request_answers_the_declared_status(booted_group) -> None:
    label, cells, base = booted_group
    got = {}
    for cell in sorted(cells, key=lambda c: c.route.path):
        method = cell.route.method.upper()
        got[cell.route.path] = _request(base, method, cell.route.path, data=b"" if method == "POST" else None)
    print(f"{label} own-method bare sweep:", got)
    wrong = {p: (s, EXPECTED_BARE_STATUS[p]) for p, s in got.items() if s != EXPECTED_BARE_STATUS[p]}
    assert not wrong, (label, wrong)


def test_bare_get_never_answers_5xx(booted_group) -> None:
    label, cells, base = booted_group
    got = {c.route.path: _request(base, "GET", c.route.path) for c in cells}
    print(f"{label} bare-GET sweep:", got)
    bad = {p: s for p, s in got.items() if not s or s >= 500}
    assert not bad, (label, bad)
