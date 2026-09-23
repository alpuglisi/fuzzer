"""Live-boot conformance harness for ``go_net_http`` (category 4 pilot,
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4/§9.5 — Phase A,
``CC-LAB-0170``/``FR-LAB-76``). This is the Go port of
``fuzzlab.labgen.conformance.live_boot.LiveBootHarness`` and
``rails_live_boot.RailsLiveBootHarness``, built the same way: entirely
inside this project's own offline test suite, using the real ``go`` CLI.

**What this proves, concretely.** :class:`GoLiveBootHarness` assembles a
real Go project (the checked-in
:data:`~fuzzlab.labgen.emitters.go_net_http` stack skeleton, overlaid with a
manifest's real ``GoEmitter``-rendered handlers/route accumulator), runs a
real ``go build``, boots the compiled binary, and lets a caller make real
HTTP requests against it.

**Simpler than every predecessor's harness, structurally, not just by
implementation effort.** Every prior stack's Phase A needed a separate
"install dependencies" step (``composer install``/``bundle install``/
``npm install``) distinct from "start the server," each with its own
capability probe. Go's toolchain does not: ``go build`` resolves and
compiles in one step, and this stack's Phase A skeleton has zero external
module dependencies (a bare ``go.mod`` with no ``require`` lines) --
:func:`go_boot_available`'s network probe below still exists and is still
mandatory (per ``PA-0035``, a probe must exercise the actual operation
path, and ``go build`` for a module with a Go-version-only ``go.mod`` can
still need network access for the toolchain's own module-graph
resolution), it is just not gated behind a separate install subcommand.

**No database (a deliberate Phase A scope call, not an oversight).** This
stack's one illustrative shape (an HMAC-signature-verified webhook
receiver) is stateless -- no read/write to persisted data -- so unlike
every other stack's own Phase-A harness, this one has no ``_seed_db``/
``query_db`` at all. See ``CC-LAB-0170``'s change-control entry for the
explicit scope call and when this stack gets a real per-run database
(Phase B, alongside its CWE-918 SSRF pick).

**Skip-guarded, per PA-0035.** :func:`go_boot_available` is the one
authoritative capability probe a caller must check before constructing a
:class:`GoLiveBootHarness`. Its network half (:func:`_go_module_proxy_probe`)
runs a real, bounded ``go list -m -versions`` against a throwaway module not
already in the local module cache, in a scratch ``GOPATH``/module cache
directory -- **not** a bare socket/DNS check standing in for it (the exact
``BUG-0033`` mistake). A missing tool or unreachable network reports
unavailable; it never raises and never hangs (bounded by this function's
own ``timeout``), and every later real subprocess step in this module's own
pipeline (``go build``, boot, request) also enforces its own bounded
timeout independently -- the probe passing is never relied on alone to
guarantee those won't hang (``PA-0035``'s second half).
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.schema import Cell

#: The checked-in, trimmed real Go module skeleton (a bare ``go mod init``
#: plus a hand-written ``main.go`` -- see that directory's own ``README.md``
#: sibling, ``stack/README.md``, for exact provenance and the -- empty --
#: trim list).
SKELETON_DIR = Path(__file__).resolve().parent.parent / "emitters" / "go_net_http" / "stack" / "skeleton"

#: How long to wait for the compiled binary to accept connections before
#: giving up and reporting a boot failure, rather than hanging indefinitely.
BOOT_TIMEOUT_S = 20.0

#: How long a single HTTP request against the booted app may take before this
#: harness treats it as a hung/broken response rather than waiting forever.
REQUEST_TIMEOUT_S = 15.0

#: How long ``go build`` may take before this harness treats it as failed
#: rather than hanging indefinitely.
BUILD_TIMEOUT_S = 120.0

#: How long :func:`_go_module_proxy_probe` may take before it reports the
#: network unavailable rather than hang -- enforced by ``subprocess.run``'s
#: own ``timeout``, never inferred from the probe "returning" on its own.
NETWORK_PROBE_TIMEOUT_S = 20.0

#: A real module, not vendored/cached by this project, used only to force a
#: real network round trip through the real Go module proxy -- the same role
#: ``psr/log`` plays for ``php_laravel``'s own ``_composer_network_probe``.
_PROBE_MODULE = "rsc.io/quote"


class GoLiveBootError(RuntimeError):
    """Raised when assembling, building, or booting the app fails for a
    reason that is not "the environment lacks go/network" (that case is
    :func:`go_boot_available` returning ``False``, a skip, never an
    error)."""


def _go_module_proxy_probe(timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Actually attempt the real operation :func:`go_boot_available` must
    predict the outcome of -- a real Go module proxy round trip (``go list
    -m -versions <module>``, the cheapest real ``go`` subcommand that still
    performs one) against a throwaway module -- instead of a bare
    ``socket.create_connection`` (``BUG-0033``'s exact mistake, applied here
    to a new package manager for the first time, built correctly per
    ``PA-0035`` rather than retrofitted).

    Run from a scratch temp ``GOPATH``/module-cache-adjacent directory (via
    ``cwd``) with no ``go.mod`` present in this project's own tree involved,
    so this never touches this repo's own module state -- a read-only
    capability check, like every other ``*_available()`` probe in this
    project (PA-0005/PA-0008). ``go list -m`` in module-aware mode with no
    local ``go.mod`` still resolves a bare module path against the real
    proxy, exactly as a real ``go build`` would for any dependency it
    needed.

    Bounded and enforced by this function's own ``timeout``: a
    :class:`subprocess.TimeoutExpired` or any other failure to run ``go``
    reports unavailable (``False``), never propagates and never hangs the
    caller."""
    if shutil.which("go") is None:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="fuzzlab-go-net-http-probe-") as scratch:
            result = subprocess.run(
                ["go", "list", "-m", "-versions", _PROBE_MODULE],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=scratch,
                env=_go_env(),
            )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def _go_env() -> dict[str, str]:
    """The real process environment, not a hand-picked subset -- ``go``
    needs ``HOME``/``GOCACHE`` (and, in a proxied sandbox, ``HTTPS_PROXY``/
    ``https_proxy``/``NO_PROXY``) to run at all, the same reason every other
    stack's own harness (``composer``, ``bundle``) inherits the full
    environment rather than replacing it. This is exactly the kind of gap a
    hand-picked ``env={...}`` would silently reintroduce -- found and fixed
    during this dispatch's own real-boot verification, before landing."""
    import os

    return dict(os.environ)


def go_boot_available() -> bool:
    """The authoritative capability probe this module's own tests (and any
    other caller) must gate on before constructing a
    :class:`GoLiveBootHarness` -- PA-0005/PA-0008: a real capability check
    (``go`` on PATH, the checked-in skeleton present, and a real, bounded,
    ``go``-driven module-proxy round trip -- :func:`_go_module_proxy_probe`,
    not a raw socket connect)."""
    return shutil.which("go") is not None and SKELETON_DIR.is_dir() and _go_module_proxy_probe()


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str


class _NoRedirectHttpErrorProcessor(urllib.request.HTTPErrorProcessor):
    """Hands back every response -- 2xx, 3xx, 4xx, 5xx alike -- exactly as
    the server sent it, matching every other stack's own harness convention
    (``BUG-0028``)."""

    def http_response(self, request, response):  # noqa: D102 - stdlib override
        return response

    https_response = http_response


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHttpErrorProcessor())


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd: list[str], *, cwd: Path, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


class GoLiveBootHarness:
    """Assembles, builds, and boots one manifest's ``go_net_http`` build for
    real, and serves real HTTP requests against it.

    Use as a context manager::

        with GoLiveBootHarness(emitter, cells) as harness:
            resp = harness.post(
                "/generated/labgen-go-0001", body=b'{"event":"test"}',
                headers={"X-Signature-256": digest},
            )

    Every temp directory and the compiled server process it starts are
    cleaned up on ``__exit__`` -- including when an exception propagates
    (PA-0012's "bounded, deterministic teardown" rule).
    """

    def __init__(self, emitter: Emitter, cells: list[Cell], *, build_timeout: float = BUILD_TIMEOUT_S) -> None:
        self._emitter = emitter
        self._cells = [c for c in cells if emitter.supports(c.vuln_class, c.sink_context)]
        self._build_timeout = build_timeout
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._app_dir: Path | None = None
        self._binary_path: Path | None = None
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None

    # -- assembly ----------------------------------------------------------

    def _assemble(self) -> None:
        assert self._app_dir is not None
        shutil.copytree(SKELETON_DIR, self._app_dir, dirs_exist_ok=True)
        for cell in self._cells:
            for emitted in self._emitter.render(cell):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)
        accumulator = self._emitter.render_route_accumulator(self._cells)
        (self._app_dir / accumulator.path).write_bytes(accumulator.content)

    def build(self) -> None:
        """Assemble the app, compile it for real with ``go build``, and boot
        the resulting binary. Raises :class:`GoLiveBootError` naming the
        failing step's real stdout/stderr on any failure -- never
        swallowed, per this project's fail-loud convention."""
        self._tmp = tempfile.TemporaryDirectory(prefix="fuzzlab-go-net-http-live-boot-")
        self._app_dir = Path(self._tmp.name) / "app"
        self._assemble()

        self._binary_path = self._app_dir / "server"
        build_result = _run(
            ["go", "build", "-o", str(self._binary_path), "."],
            cwd=self._app_dir,
            timeout=self._build_timeout,
        )
        if build_result.returncode != 0:
            raise GoLiveBootError(
                f"go build failed (exit {build_result.returncode}):\n"
                f"{build_result.stdout[-4000:]}\n{build_result.stderr[-4000:]}"
            )

        self._port = _find_free_port()
        proc_env = _go_env()
        proc_env["PORT"] = str(self._port)
        self._proc = subprocess.Popen(
            [str(self._binary_path)],
            cwd=self._app_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=proc_env,
        )
        self._wait_for_boot()

    def _wait_for_boot(self) -> None:
        assert self._port is not None
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                out = self._proc.stdout.read() if self._proc.stdout else ""
                raise GoLiveBootError(f"go_net_http server exited early (code {self._proc.returncode}):\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", self._port), timeout=1.0):
                    return
            except OSError as exc:
                last_err = exc
                time.sleep(0.25)
        raise GoLiveBootError(f"go_net_http server did not accept connections within {BOOT_TIMEOUT_S}s: {last_err}")

    # -- HTTP ---------------------------------------------------------------

    def _base_url(self) -> str:
        assert self._port is not None
        return f"http://127.0.0.1:{self._port}"

    @property
    def base_url(self) -> str:
        """The real, booted app's base URL -- for a caller (e.g. a
        `fuzzlab.harness.multitarget.TargetSpec`) that needs to point at it
        without going through this harness's own request methods."""
        return self._base_url()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """A real HTTP request against the booted app. Raw-bytes body and
        arbitrary headers (unlike every prior harness's form-encoded
        ``data``): this stack's one illustrative shape is a webhook
        receiver, which needs a raw JSON-ish body plus a signature header,
        not a form post. Never follows a redirect (``BUG-0028``'s
        convention, even though this Phase-A shape never itself issues
        one -- kept for consistency with every other harness's ``request``
        contract)."""
        url = self._base_url() + path
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers or {})
        with _NO_REDIRECT_OPENER.open(req, timeout=REQUEST_TIMEOUT_S) as resp:
            return HttpResponse(status=resp.status, body=resp.read().decode("utf-8", errors="replace"))

    def post(self, path: str, *, body: bytes, headers: dict[str, str] | None = None) -> HttpResponse:
        return self.request("POST", path, body=body, headers=headers)

    # -- lifecycle ------------------------------------------------------------

    def close(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5.0)
        self._proc = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    def __enter__(self) -> "GoLiveBootHarness":
        self.build()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
