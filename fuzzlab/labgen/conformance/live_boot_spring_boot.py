"""Live-boot conformance harness for ``spring_boot`` (`CC-LAB-0130`,
TrackerNest, category 3's Atlassian pick).

Mirrors ``fuzzlab.labgen.conformance.live_boot``'s ``LiveBootHarness`` for
``php_laravel`` -- a real, checked-in project skeleton, assembled with a
manifest's real rendered output, a real dependency install (``mvn package``),
a real process boot, and real HTTP requests against it -- kept as an
independent module (not folded into ``live_boot.py``) since that module's own
docstring and every one of its symbols (``SKELETON_DIR``, ``_composer_
network_probe``, ``SEED_USERNAME``, ...) are explicitly ``php_laravel``-
specific; a future cross-stack refactor that lifts a shared base out of both
modules is exactly the kind of judgment call
``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` sec 2 flags as "make once
both are visible side by side," not decided here.

**What this proves, concretely.** :class:`SpringBootLiveBootHarness`
assembles a real Spring Boot project (the checked-in
:data:`SKELETON_DIR` skeleton, overlaid with one cell's real
``SpringBootEmitter``-rendered controller), runs a real ``mvn package``,
boots the resulting executable jar for real (``java -jar``), and lets a
caller make real HTTP requests against it -- the same bar `php_laravel`'s
very first live-boot test set (`CC-LAB-0054`).

**One cell per harness instance, by design -- not a limitation of this
module.** ``ssti_spring_boot_sample.yaml``'s two cells (`LABGEN-SSTI-0001`
vulnerable, `LABGEN-SSTI-0002` secure) share the same route
(``GET /wiki/pages/render``), so booting both into one running app would be
a real route collision -- this harness is built, and its own test uses it,
the same way `tests/test_labgen_mass_assignment_live_boot.py` already
established for `php_laravel`'s own same-route twin pairs: construct one
harness per cell, boot, request, tear down, then do the same for the other
cell, and compare the two real responses.

**Capability probe (`spring_boot_boot_available()`), per `PA-0035`/`BUG-0033`.**
A real, bounded Maven Central dependency-resolution round trip
(``mvn dependency:get`` for a real, small, already-declared artifact) --
never a raw socket/DNS check standing in for it. Confirmed working in this
build sandbox on 2026-09-22 (see `CC-LAB-0130`'s change-control entry for
the exact commands); if unreachable in a future environment, this probe
returns ``False`` and every caller SKIPs, per this project's `[design]`-only
fallback convention for a newly-built stack (matching `python_fastapi`/
`node_express`'s own stated Tier 1/2 status).
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.schema import Cell

#: The checked-in, real, minimal Spring Boot project skeleton -- see this
#: directory's sibling ``stack/README.md`` for exact provenance (hand-
#: authored to the shape Spring Initializr would produce, since
#: ``start.spring.io`` itself is unreachable from this build sandbox; every
#: dependency coordinate/version is real, resolved live against Maven
#: Central).
SKELETON_DIR = (
    Path(__file__).resolve().parent.parent / "emitters" / "spring_boot" / "stack" / "skeleton"
)

#: How long a real ``mvn package`` may take before this harness gives up --
#: generous, matching ``live_boot.py``'s own ``install_timeout`` default
#: (240.0s for ``composer install``); a cold local Maven repository (first
#: run) can take a comparable amount of real network+compile time.
BUILD_TIMEOUT_S = 240.0
BOOT_TIMEOUT_S = 30.0
REQUEST_TIMEOUT_S = 15.0
NETWORK_PROBE_TIMEOUT_S = 60.0


class LiveBootError(RuntimeError):
    """Raised when assembling, building, or booting the app fails for a
    reason that is not "the environment lacks maven/java/network" (that case
    is :func:`spring_boot_boot_available` returning ``False``, a skip, never
    an error)."""


def _maven_network_probe(timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Actually attempt the real operation :func:`spring_boot_boot_available`
    must predict the outcome of -- a real, bounded Maven Central dependency
    round trip through **Maven's own HTTP client** (``mvn dependency:get``
    for a small, real, already-declared artifact this skeleton's own
    ``pom.xml`` uses), instead of a bare socket/DNS check (``BUG-0033``'s
    exact failure mode, applied here to a second package manager per
    `PA-0035`'s "build it correctly the first time" rule).

    Run from the skeleton directory itself (not a scratch cwd) so Maven
    resolves against the real ``pom.xml``'s parent/repository configuration.
    Unlike ``live_boot.py``'s composer probe, this does populate the local
    ``~/.m2`` cache (``dependency:get`` downloads the artifact) rather than
    only querying metadata -- a harmless, idempotent local side effect (the
    same cache a real ``mvn package`` uses and warms identically), never a
    mutation of this repo's own tracked state, so it still fits this
    project's "a real capability check, safe to run anywhere" convention
    (PA-0005/PA-0008) even though it is not read-only in the narrower sense
    composer's ``show -a`` is.

    Bounded and enforced by this function's own ``timeout``: a
    :class:`subprocess.TimeoutExpired` or any other failure to run ``mvn``
    reports unavailable (``False``), never propagates and never hangs the
    caller."""
    if shutil.which("mvn") is None:
        return False
    try:
        result = subprocess.run(
            [
                "mvn", "-q", "-B",
                "dependency:get",
                "-Dartifact=ognl:ognl:3.4.13",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=SKELETON_DIR,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def spring_boot_boot_available() -> bool:
    """The authoritative capability probe a caller (chiefly the pytest
    suite) must check before constructing a
    :class:`SpringBootLiveBootHarness` -- PA-0005/PA-0008: a real capability
    check (java + mvn on PATH, the skeleton present, and a real, bounded,
    Maven-driven Maven Central round trip -- :func:`_maven_network_probe`,
    not a raw socket connect)."""
    return (
        shutil.which("java") is not None
        and shutil.which("mvn") is not None
        and SKELETON_DIR.is_dir()
        and _maven_network_probe()
    )


class _NoRedirectHttpErrorProcessor(urllib.request.HTTPErrorProcessor):
    """Hands back every response -- 2xx, 3xx, 4xx, 5xx alike -- exactly as
    the server sent it, matching ``live_boot.py``'s own
    ``_NoRedirectHttpErrorProcessor`` (``BUG-0028``)."""

    def http_response(self, request, response):  # noqa: D102 - stdlib override
        return response

    https_response = http_response


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHttpErrorProcessor())


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd: list[str], *, cwd: Path, timeout: float) -> subprocess.CompletedProcess:
    """Run a real subprocess step of the live-boot pipeline with an enforced,
    bounded ``timeout`` -- mirrors ``live_boot.py``'s own ``_run``
    (`PA-0035`: a passing capability probe is not a substitute for every
    later real subprocess operation also being bounded on its own)."""
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LiveBootError(
            f"{cmd[0]} did not complete within {timeout}s (cmd={cmd!r}): "
            f"stdout={exc.stdout!r} stderr={exc.stderr!r}"
        ) from exc


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str
    #: Response headers, case-insensitive-original-cased, first value wins
    #: on a repeat (`CC-LAB-0191`, additive -- every pre-existing caller
    #: keeps working unchanged, since this is a new field with a default).
    #: Needed by this stack's first `unrestricted_file_upload` cell's own
    #: differential test, which must read the served `Content-Type` back
    #: (whether the vulnerable twin derived it from the caller's filename
    #: extension, or the secure twin derived it from the real sniffed
    #: bytes) -- something no pre-existing `spring_boot` cell's own
    #: live-boot test needed to check.
    headers: dict[str, str] = field(default_factory=dict)


class SpringBootLiveBootHarness:
    """Assembles, builds, and boots exactly one cell's ``spring_boot`` build
    for real, and serves real HTTP requests against it.

    Use as a context manager::

        with SpringBootLiveBootHarness(emitter, cell) as harness:
            resp = harness.get("/wiki/pages/render", params={"macroExpr": "7*7"})

    Every temp directory and the ``java -jar`` process it starts are cleaned
    up on ``__exit__``, including when an exception propagates (PA-0012).
    Takes exactly **one** cell, not a list -- see this module's own
    docstring for why (a same-route twin pair would collide if booted
    together).
    """

    def __init__(
        self,
        emitter: Emitter,
        cell_or_cells: Cell | list[Cell],
        *,
        app: str | None = None,
        build_timeout: float = BUILD_TIMEOUT_S,
    ) -> None:
        """``app`` (CC-LAB-0244, plan §2d) is additive: omitted (the
        default), this is the original single-cell harness, unchanged for
        every existing caller -- ``cell_or_cells`` is exactly one
        :class:`Cell`. Given ``app`` (one of ``app_site.APP_REGISTRY``),
        ``cell_or_cells`` is that app's whole cell list, assembled as a
        real site build: every cell rendered with ``emitter.site_build =
        True`` (twin-suffixed secure-twin URLs, so same-route pairs never
        collide) plus the app's own generated ``SiteController`` (this
        module's own precedent for what a same-route twin pair needs, R1).
        """
        self._app = app
        if app is None:
            cell = cell_or_cells
            assert isinstance(cell, Cell), "cell_or_cells must be one Cell when app is not given"
            if not emitter.supports(cell.vuln_class, cell.sink_context):
                raise ValueError(f"{cell.cell_id}: emitter does not support this cell's shape")
            self._cells = [cell]
        else:
            cells = cell_or_cells
            assert not isinstance(cells, Cell), "cell_or_cells must be a list of Cells when app is given"
            self._cells = list(cells)
            for c in self._cells:
                if not emitter.supports(c.vuln_class, c.sink_context):
                    raise ValueError(f"{c.cell_id}: emitter does not support this cell's shape")
            emitter.site_build = True
        self._emitter = emitter
        self._build_timeout = build_timeout
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._app_dir: Path | None = None
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None

    @property
    def app_dir(self) -> Path:
        """The assembled app's real root directory (`CC-LAB-0132`) -- valid
        only after ``build()``/``__enter__`` has run, and until ``close()``.
        Public so a caller can reach real build output the harness itself
        does not expose a dedicated method for (e.g. `target/classes`, for
        the insecure-deserialization cell's live-boot test to run a small,
        already-compiled Java helper against this exact assembled tree) --
        the same private-attribute access
        `tests/test_labgen_conformance_live_boot_mariadb.py` already reaches
        for on `LiveBootHarness._app_dir` (`# noqa: SLF001`), made a real,
        public, documented property here instead of repeating that pattern
        a second time."""
        assert self._app_dir is not None, "app_dir is only valid inside a build()'d/entered harness"
        return self._app_dir

    # -- assembly ------------------------------------------------------------

    def _assemble(self) -> None:
        assert self._app_dir is not None
        shutil.copytree(SKELETON_DIR, self._app_dir, dirs_exist_ok=True)
        for cell in self._cells:
            for emitted in self._emitter.render(cell):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)
        if self._app is not None:
            for emitted in self._emitter.render_site(self._cells, self._app):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)

    def build(self) -> None:
        """Assemble the app, build a real executable jar, and boot it.
        Raises :class:`LiveBootError` naming the failing step's real
        stdout/stderr on any failure -- never swallowed."""
        self._tmp = tempfile.TemporaryDirectory(prefix="fuzzlab-spring-boot-live-boot-")
        self._app_dir = Path(self._tmp.name) / "app"
        self._assemble()

        package_result = _run(
            ["mvn", "-q", "-B", "package", "-DskipTests"],
            cwd=self._app_dir,
            timeout=self._build_timeout,
        )
        if package_result.returncode != 0:
            raise LiveBootError(
                f"mvn package failed (exit {package_result.returncode}):\n"
                f"{package_result.stdout[-4000:]}\n{package_result.stderr[-4000:]}"
            )

        self._port = _find_free_port()
        jar_path = self._app_dir / "target" / "trackernest.jar"
        self._proc = subprocess.Popen(
            ["java", "-jar", str(jar_path), f"--server.port={self._port}"],
            cwd=self._app_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_boot()

    def _wait_for_boot(self) -> None:
        assert self._port is not None
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                out = self._proc.stdout.read() if self._proc.stdout else ""
                raise LiveBootError(f"java -jar exited early (code {self._proc.returncode}):\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", self._port), timeout=1.0):
                    return
            except OSError as exc:
                last_err = exc
                time.sleep(0.25)
        raise LiveBootError(f"trackernest.jar did not accept connections within {BOOT_TIMEOUT_S}s: {last_err}")

    # -- HTTP ------------------------------------------------------------------

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
        params: dict[str, str] | None = None,
        data: bytes | None = None,
        content_type: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """A real HTTP request against the booted app. Never follows a
        redirect (matching ``live_boot.py``'s own convention, `BUG-0028`).

        ``data``/``content_type`` (`CC-LAB-0131`): a raw request body for a
        cell whose payload cannot travel as a query parameter (e.g. an XML
        document with a DOCTYPE) -- sent exactly as given, never form-
        encoded, unlike ``live_boot.py``'s own ``post()`` (which is
        form-body-only, matching `php_laravel`'s cells; this stack's first
        POST cell needs a raw body instead).

        ``headers`` (`CC-LAB-0187`): extra request headers on top of
        ``Content-Type`` -- this stack's first cell needing a caller-
        identity header (the ``access_control``/IDOR shape's fixed demo
        ``X-Account-Id`` header, mirroring ``go_net_http``'s own fixed demo
        ``X-Broadcaster-Id``). Optional and additive: every pre-existing
        caller keeps working unchanged with no ``headers`` argument."""
        url = self._base_url() + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req_headers = {"Content-Type": content_type} if content_type else {}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=req_headers)
        with _NO_REDIRECT_OPENER.open(req, timeout=REQUEST_TIMEOUT_S) as resp:
            resp_headers = dict(resp.headers.items())
            return HttpResponse(
                status=resp.status,
                body=resp.read().decode("utf-8", errors="replace"),
                headers=resp_headers,
            )

    def get(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("GET", path, params=params, headers=headers)

    def post(self, path: str, *, data: bytes, content_type: str = "application/xml") -> HttpResponse:
        """A real HTTP POST with a raw request body (`CC-LAB-0131`) -- e.g.
        an XML document, sent byte-for-byte, never form-encoded."""
        return self.request("POST", path, data=data, content_type=content_type)

    # -- lifecycle ---------------------------------------------------------------

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

    def __enter__(self) -> "SpringBootLiveBootHarness":
        self.build()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
