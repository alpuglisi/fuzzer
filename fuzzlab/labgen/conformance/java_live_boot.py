"""Live-boot conformance harness for ``java_spring_boot`` (category 4 pilot,
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §9.4/§9.5 — Phase A,
``CC-LAB-0171``/``FR-LAB-77``). This is the Java/Maven port of
``fuzzlab.labgen.conformance.go_live_boot.GoLiveBootHarness``, built the
same way: entirely inside this project's own offline test suite, using the
real ``mvn``/``java`` CLIs.

**What this proves, concretely.** :class:`JavaLiveBootHarness` assembles a
real Maven/Spring Boot project (the checked-in
:data:`~fuzzlab.labgen.emitters.java_spring_boot` stack skeleton, overlaid
with a manifest's real ``JavaEmitter``-rendered controller classes), runs a
real ``mvn package`` (resolving `spring-boot-starter-web` and friends
against the real Maven Central through this sandbox's proxy -- verified
reachable this session via a real ``mvn dependency:resolve``, not a raw
``curl`` probe, which separately returned a real ``429`` from Maven
Central directly), boots the packaged executable jar, and lets a caller
make real HTTP requests against it.

**No accumulator-assembly step, unlike every routed emitter's own
harness.** ``go_net_http``'s harness (and ``node_express``'s/
``ruby_rails``'s) each render and write a separate shared route-
registration file after writing every cell's own file. Spring Boot's
component scanning needs no such file (see
:mod:`fuzzlab.labgen.emitters.java_spring_boot`'s own module docstring for
why) -- this harness's ``_assemble`` step is therefore just "write every
supported cell's one rendered file," nothing more.

**No database (a deliberate Phase A scope call, matching
``go_net_http``'s own).** This stack's one illustrative shape
(Jackson-deserialize a POST body, acknowledge it) is stateless -- no
read/write to persisted data -- so this harness has no ``_seed_db``/
``query_db`` at all. See ``CC-LAB-0171``'s change-control entry for the
explicit scope call and when this stack gets a real per-run database
(Phase B).

**Skip-guarded, per PA-0035.** :func:`java_boot_available` is the one
authoritative capability probe a caller must check before constructing a
:class:`JavaLiveBootHarness`. Its network half
(:func:`_maven_central_probe`) runs a real, bounded ``mvn dependency:go-
offline`` against the checked-in skeleton's own ``pom.xml`` in a scratch
copy -- the same real dependency (`spring-boot-starter-web` 3.4.1) the
harness's own ``mvn package`` will need, resolved through **the real
Maven client**, never a bare socket/DNS check standing in for it (the
exact ``BUG-0033`` mistake, avoided here for a third package manager,
after the environment-inheritance bug this same category-4 pilot's own
``go_net_http`` dispatch found and fixed in its own probe -- applied
proactively here from the first commit rather than rediscovered). A
missing tool or unreachable network reports unavailable; it never raises
and never hangs (bounded by this function's own ``timeout``), and every
later real subprocess step in this module's own pipeline (``mvn
package``, boot, request) also enforces its own bounded timeout
independently.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.schema import Cell

#: The checked-in, trimmed real Maven/Spring Boot skeleton (see that
#: directory's own ``README.md`` sibling for exact provenance).
SKELETON_DIR = Path(__file__).resolve().parent.parent / "emitters" / "java_spring_boot" / "stack" / "skeleton"

#: How long to wait for the packaged jar to accept connections before
#: giving up and reporting a boot failure -- JVM/Spring Boot cold-starts
#: noticeably slower than a compiled Go binary, so this is longer than
#: `go_live_boot.py`'s own `BOOT_TIMEOUT_S`.
BOOT_TIMEOUT_S = 45.0

#: How long a single HTTP request against the booted app may take before
#: this harness treats it as a hung/broken response rather than waiting
#: forever.
REQUEST_TIMEOUT_S = 15.0

#: How long ``mvn package`` may take before this harness treats it as
#: failed rather than hanging indefinitely -- generous, since a cold
#: dependency-resolution run (uncached ``~/.m2``) is slower than a warm one.
BUILD_TIMEOUT_S = 240.0

#: How long :func:`_maven_central_probe` may take before it reports the
#: network unavailable rather than hang.
NETWORK_PROBE_TIMEOUT_S = 60.0


class JavaLiveBootError(RuntimeError):
    """Raised when assembling, building, or booting the app fails for a
    reason that is not "the environment lacks maven/java/network" (that
    case is :func:`java_boot_available` returning ``False``, a skip, never
    an error)."""


def _maven_env() -> dict[str, str]:
    """The real process environment, not a hand-picked subset -- Maven and
    the JVM need ``HOME``/``JAVA_TOOL_OPTIONS`` (this sandbox's proxy/
    truststore configuration is injected via ``JAVA_TOOL_OPTIONS``, per
    ``/root/.ccr/README.md``) to run at all. Replacing the environment
    instead of inheriting it is exactly the bug `CC-LAB-0170` found and
    fixed in its own Go probe -- applied correctly here from the start."""
    return dict(os.environ)


def _maven_central_probe(timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Actually attempt the real operation :func:`java_boot_available` must
    predict the outcome of -- a real Maven Central round trip through
    **Maven's own HTTP client** (``mvn dependency:go-offline`` against the
    checked-in skeleton's own ``pom.xml``, copied to a scratch directory so
    this never touches this repo's own build state) -- instead of a bare
    socket connect or an unauthenticated raw HTTP probe (this session's own
    research found Maven Central returns a real ``429`` to a bare ``curl``
    request against it directly; the real ``mvn`` client is what this
    harness's own ``mvn package`` will use, and is confirmed to work).

    Bounded and enforced by this function's own ``timeout``: a
    :class:`subprocess.TimeoutExpired` or any other failure to run ``mvn``
    reports unavailable (``False``), never propagates and never hangs the
    caller."""
    if shutil.which("mvn") is None or shutil.which("java") is None:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="fuzzlab-java-spring-boot-probe-") as scratch:
            scratch_path = Path(scratch)
            shutil.copy2(SKELETON_DIR / "pom.xml", scratch_path / "pom.xml")
            result = subprocess.run(
                ["mvn", "-q", "-B", "dependency:go-offline"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=scratch_path,
                env=_maven_env(),
            )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def java_boot_available() -> bool:
    """The authoritative capability probe this module's own tests (and any
    other caller) must gate on before constructing a
    :class:`JavaLiveBootHarness` -- PA-0005/PA-0008: a real capability
    check (``mvn``/``java`` on PATH, the checked-in skeleton present, and a
    real, bounded, ``mvn``-driven Maven Central round trip --
    :func:`_maven_central_probe`, not a raw socket/HTTP connect)."""
    return (
        shutil.which("mvn") is not None
        and shutil.which("java") is not None
        and SKELETON_DIR.is_dir()
        and _maven_central_probe()
    )


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
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=_maven_env())


class JavaLiveBootHarness:
    """Assembles, packages, and boots one manifest's ``java_spring_boot``
    build for real, and serves real HTTP requests against it.

    Use as a context manager::

        with JavaLiveBootHarness(emitter, cells) as harness:
            resp = harness.post(
                "/generated/labgen-jv-0001", body=b'{"profileId":"p1"}',
                headers={"Content-Type": "application/json"},
            )

    Every temp directory and the booted JVM process it starts are cleaned
    up on ``__exit__`` -- including when an exception propagates (PA-0012's
    "bounded, deterministic teardown" rule).
    """

    def __init__(self, emitter: Emitter, cells: list[Cell], *, build_timeout: float = BUILD_TIMEOUT_S) -> None:
        self._emitter = emitter
        self._cells = [c for c in cells if emitter.supports(c.vuln_class, c.sink_context)]
        self._build_timeout = build_timeout
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._app_dir: Path | None = None
        self._jar_path: Path | None = None
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None

    # -- assembly ----------------------------------------------------------

    def _assemble(self) -> None:
        assert self._app_dir is not None
        shutil.copytree(SKELETON_DIR, self._app_dir, dirs_exist_ok=True)
        # No accumulator step -- see the module docstring: Spring Boot's
        # component scanning discovers every generated `@RestController`
        # class on its own, at boot.
        for cell in self._cells:
            for emitted in self._emitter.render(cell):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)

    def build(self) -> None:
        """Assemble the app, package it for real with ``mvn package``, and
        boot the resulting executable jar. Raises :class:`JavaLiveBootError`
        naming the failing step's real stdout/stderr on any failure --
        never swallowed, per this project's fail-loud convention."""
        self._tmp = tempfile.TemporaryDirectory(prefix="fuzzlab-java-spring-boot-live-boot-")
        self._app_dir = Path(self._tmp.name) / "app"
        self._assemble()

        package_result = _run(
            ["mvn", "-q", "-B", "package", "-DskipTests"],
            cwd=self._app_dir,
            timeout=self._build_timeout,
        )
        if package_result.returncode != 0:
            raise JavaLiveBootError(
                f"mvn package failed (exit {package_result.returncode}):\n"
                f"{package_result.stdout[-4000:]}\n{package_result.stderr[-4000:]}"
            )

        jars = sorted((self._app_dir / "target").glob("*.jar"))
        if not jars:
            raise JavaLiveBootError(f"mvn package produced no jar under {self._app_dir / 'target'}")
        self._jar_path = jars[0]

        self._port = _find_free_port()
        proc_env = _maven_env()
        self._proc = subprocess.Popen(
            ["java", "-jar", str(self._jar_path), f"--server.port={self._port}"],
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
                raise JavaLiveBootError(
                    f"java_spring_boot server exited early (code {self._proc.returncode}):\n{out}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self._port), timeout=1.0):
                    return
            except OSError as exc:
                last_err = exc
                time.sleep(0.5)
        raise JavaLiveBootError(
            f"java_spring_boot server did not accept connections within {BOOT_TIMEOUT_S}s: {last_err}"
        )

    # -- HTTP ---------------------------------------------------------------

    def _base_url(self) -> str:
        assert self._port is not None
        return f"http://127.0.0.1:{self._port}"

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """A real HTTP request against the booted app. Never follows a
        redirect (``BUG-0028``'s convention, kept for consistency with
        every other harness's ``request`` contract, even though this
        Phase-A shape never itself issues one)."""
        url = self._base_url() + path
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers or {})
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=REQUEST_TIMEOUT_S) as resp:
                return HttpResponse(status=resp.status, body=resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            # Spring's default error handler still returns a real response
            # body (a JSON error payload) for a 4xx/5xx it raises rather
            # than routes normally -- surfaced the same way as a 2xx here,
            # never swallowed as an exception, matching this harness's own
            # "hand back every response exactly as sent" contract.
            return HttpResponse(status=exc.code, body=exc.read().decode("utf-8", errors="replace"))

    def post(self, path: str, *, body: bytes, headers: dict[str, str] | None = None) -> HttpResponse:
        return self.request("POST", path, body=body, headers=headers)

    # -- lifecycle ------------------------------------------------------------

    def close(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=10.0)
        self._proc = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    def __enter__(self) -> "JavaLiveBootHarness":
        self.build()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
