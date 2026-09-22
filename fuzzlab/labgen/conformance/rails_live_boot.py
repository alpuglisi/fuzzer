"""Live-boot conformance harness for ``ruby_rails`` (category 1 e-commerce
pilot, ``docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`` §2/§9.4a/§9.5 --
Phase A). This is the Rails port of
``fuzzlab.labgen.conformance.live_boot.LiveBootHarness``, built the same way
``php_laravel``'s own harness was built: entirely inside this project's own
offline test suite, using Rails' own development server (``bin/rails
server``, backed by Puma) and a per-run SQLite database.

**What this proves, concretely.** :class:`RailsLiveBootHarness` assembles a
real Rails 8.1 project (the checked-in
:data:`~fuzzlab.labgen.emitters.ruby_rails.stack` skeleton, overlaid with a
manifest's real ``RailsEmitter``-rendered controllers/views/routes), runs a
real ``bundle install``, migrates a real per-run SQLite database (``bin/rails
db:prepare``), boots a real ``bin/rails server`` process, and lets a caller
make real HTTP requests against it.

**Why SQLite here.** Same reasoning as the Laravel harness's own module
docstring: this proves the strictly narrower (but, before this dispatch,
entirely unproven) claim that a ``ruby_rails``-emitted build actually
**boots and serves**, and that a payload differential is observable end to
end over a real HTTP round trip -- not an oracle-grade vulnerable/secure
verdict against the stack's eventual real target database engine (this
category has no single external target to mirror the way ``php_laravel``
mirrors ``puppy-fort-factory``'s own MariaDB -- Shopify/Walmart are external
sites, not a checked-in schema fixture). SQLite is also Rails' own
``--minimal`` generator default here, unlike ``php_laravel`` where SQLite
required overriding the real lab's MySQL ``.env`` default.

**Skip-guarded, per PA-0035 (the ``BUG-0033`` rule, applied correctly the
first time for this stack's package manager).** :func:`rails_boot_available`
is the one authoritative capability probe a caller must check before
constructing a :class:`RailsLiveBootHarness`. Its network half
(:func:`_bundle_network_probe`) runs a real, bounded ``bundle lock`` (no
``--local``) against a throwaway, not-already-installed-locally gem in a
scratch directory -- **not** a bare socket/DNS check standing in for it.
``bundle lock`` is the right choice of "cheapest real subcommand that still
performs the actual operation" for this package manager specifically
because it is the literal first phase of ``bundle install`` (dependency
resolution against RubyGems' real compact-index HTTP API, honoring
``HTTPS_PROXY``/``https_proxy`` exactly as a real ``bundle install``
does) with no install side effect -- the same role ``composer show -a``
plays for ``php_laravel``'s own probe. A missing tool or unreachable
network reports unavailable; it never raises and never hangs (bounded by
this function's own ``timeout``), and every later real subprocess step in
this module's own pipeline (``bundle install``, ``bin/rails db:prepare``,
``bin/rails server``) also enforces its own bounded timeout independently --
the probe passing is never relied on alone to guarantee those won't hang
(PA-0035's second half).
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

from fuzzlab.labgen.conformance.tier1 import Tier1Case
from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.schema import Cell

#: The checked-in, trimmed real Rails 8.1 project skeleton (``rails new
#: --minimal``, dev-only tooling stripped -- see this stack's own
#: ``stack/README.md`` for the exact provenance and trim list).
SKELETON_DIR = Path(__file__).resolve().parent.parent / "emitters" / "ruby_rails" / "stack" / "skeleton"

#: How long to wait for ``bin/rails server`` to accept connections before
#: giving up and reporting a boot failure, rather than hanging indefinitely.
BOOT_TIMEOUT_S = 30.0

#: How long a single HTTP request against the booted app may take before this
#: harness treats it as a hung/broken response rather than waiting forever.
REQUEST_TIMEOUT_S = 15.0

#: How long :func:`_bundle_network_probe` may take before it reports the
#: network unavailable rather than hang -- enforced by ``subprocess.run``'s
#: own ``timeout``, never inferred from the probe "returning" on its own.
NETWORK_PROBE_TIMEOUT_S = 20.0


class RailsLiveBootError(RuntimeError):
    """Raised when assembling, installing, migrating, or booting the app
    fails for a reason that is not "the environment lacks ruby/bundler/
    network" (that case is :func:`rails_boot_available` returning ``False``,
    a skip, never an error)."""


def _bundle_network_probe(timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Actually attempt the real operation :func:`rails_boot_available` must
    predict the outcome of -- a real RubyGems dependency-resolution round
    trip through **Bundler's own HTTP client** (``bundle lock``, no
    ``--local``, against a throwaway ``Gemfile`` naming a small gem this
    sandbox does not already have locally installed/cached) -- instead of a
    bare ``socket.create_connection`` to port 443 (``BUG-0033``/PA-0035: a
    raw TCP connect can succeed on a path a real HTTPS client's configured
    proxy does not take, so it answers a different question than "will the
    real dependent operation complete in bounded time").

    ``bundle lock`` (dependency resolution only, no gem download/install) is
    the cheapest real Bundler subcommand that still performs the actual
    network fetch a real ``bundle install`` performs as its first phase --
    against a gem this probe's own scratch ``Gemfile`` names but has never
    resolved/cached before, so a stale local resolution cannot silently
    stand in for a real network round trip. Run from a scratch cwd with its
    own throwaway ``Gemfile`` -- never this repo's, or the skeleton's own --
    so this never reads/writes real project lock state, matching every
    other ``*_available()`` probe's read-only-check discipline
    (PA-0005/PA-0008).

    Bounded and enforced by this function's own ``timeout``: a
    :class:`subprocess.TimeoutExpired` or any other failure to run ``bundle``
    reports unavailable (``False``), never propagates and never hangs the
    caller.
    """
    if shutil.which("bundle") is None:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="fuzzlab-ruby-rails-net-probe-") as scratch:
            gemfile = Path(scratch) / "Gemfile"
            # `power_assert` is a small, real RubyGems package this sandbox's
            # global gemset does not already carry as a direct Rails
            # dependency (unlike e.g. `bigdecimal`, which Rails itself pulls
            # in transitively and could let a stale local resolution masquerade
            # as a fresh network round trip) -- resolving it for real forces an
            # actual RubyGems compact-index fetch.
            gemfile.write_text('source "https://rubygems.org"\ngem "power_assert"\n', encoding="utf-8")
            result = subprocess.run(
                ["bundle", "lock", "--gemfile", str(gemfile)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=scratch,
            )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def rails_boot_available() -> bool:
    """The authoritative capability probe this module's own tests (and any
    other caller) must gate on before constructing a
    :class:`RailsLiveBootHarness` -- PA-0005/PA-0008/PA-0035: a real
    capability check (``ruby``/``bundle`` on PATH, the skeleton present, and
    a real, bounded, Bundler-driven RubyGems round trip --
    :func:`_bundle_network_probe`, not a raw socket connect)."""
    return (
        shutil.which("ruby") is not None
        and shutil.which("bundle") is not None
        and SKELETON_DIR.is_dir()
        and _bundle_network_probe()
    )


class _NoRedirectHttpErrorProcessor(urllib.request.HTTPErrorProcessor):
    """Hands back every response -- 2xx, 3xx, 4xx, 5xx alike -- exactly as
    the server sent it, instead of ``urllib``'s default behavior of raising
    :class:`urllib.error.HTTPError` for non-2xx and silently *following* a
    3xx. Replicated from ``fuzzlab.labgen.conformance.live_boot`` (a private
    helper of a sibling module, not meant to be imported cross-stack) rather
    than imported, per this stack's own dispatch instructions."""

    def http_response(self, request, response):  # noqa: D102 - stdlib override
        return response

    https_response = http_response


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHttpErrorProcessor())


def _find_free_port() -> int:
    """Replicated from ``live_boot.py``'s own private helper of the same
    name (see this module's docstring for why it is replicated, not
    imported)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd: list[str], *, cwd: Path, timeout: float, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run a real subprocess step of the live-boot pipeline (``bundle
    install``, ``bin/rails db:prepare``, ...) with an enforced, bounded
    ``timeout`` on every call site -- never left to the caller to remember
    (PA-0035's second half: a passing capability probe is not a substitute
    for every later real network/subprocess operation also being bounded on
    its own)."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RailsLiveBootError(
            f"{cmd[0]} did not complete within {timeout}s (cmd={cmd!r}): "
            f"stdout={exc.stdout!r} stderr={exc.stderr!r}"
        ) from exc


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str


class RailsLiveBootHarness:
    """Assembles, installs, migrates, and boots one manifest's
    ``ruby_rails`` build for real, and serves real HTTP requests against it.

    Use as a context manager::

        with RailsLiveBootHarness(emitter, cells) as harness:
            resp = harness.get("/cell/labgen-rr-0001", params={"q": "<b>hi</b>"})

    Every temp directory and the ``bin/rails server`` process it starts are
    cleaned up on ``__exit__`` -- including when an exception propagates
    (PA-0012's bounded, deterministic teardown convention, mirroring
    ``LiveBootHarness.close``).
    """

    def __init__(
        self,
        emitter: Emitter,
        cells: list[Cell],
        *,
        install_timeout: float = 240.0,
    ) -> None:
        self._emitter = emitter
        self._cells = [c for c in cells if emitter.supports(c.vuln_class, c.sink_context)]
        self._install_timeout = install_timeout
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._app_dir: Path | None = None
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None

    # -- assembly ------------------------------------------------------------

    def _assemble(self) -> None:
        assert self._app_dir is not None
        shutil.copytree(SKELETON_DIR, self._app_dir, dirs_exist_ok=True)

        # Per-manifest generated content: every supported cell's
        # controller/view, plus the accumulated config/routes.rb -- mirrors
        # LiveBootHarness._assemble()'s own missing-assembly-step role for
        # php_laravel exactly, adapted to Rails' routes.rb DSL via
        # RouteAccumulator instead of assuming Laravel's Route::get(...)
        # syntax maps directly.
        fragments: dict[str, str] = {}
        for cell in self._cells:
            for emitted in self._emitter.render(cell):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)
            fragments[cell.cell_id] = self._emitter.route_fragment_for(cell)

        from fuzzlab.labgen.emitters.ruby_rails.route_accumulator import RouteAccumulator

        routes_file = self._app_dir / "config" / "routes.rb"
        routes_file.write_text(RouteAccumulator().render_file(fragments), encoding="utf-8")

    def _harness_env(self) -> dict[str, str]:
        """A harness-only environment layered on top of the real process
        environment: a real, freshly-generated ``SECRET_KEY_BASE`` (Rails'
        session/cookie signing secret -- generated per run, never a fixed
        literal, exactly like ``LiveBootHarness``'s own real ``APP_KEY`` via
        ``artisan key:generate``) and ``RAILS_ENV=development`` (this
        skeleton carries no ``config/master.key``/``credentials.yml.enc``,
        so nothing requires ``production``'s stricter secret-key handling;
        see ``stack/README.md`` for why those files are not checked in)."""
        import os
        import secrets

        env = dict(os.environ)
        env["RAILS_ENV"] = "development"
        env["SECRET_KEY_BASE"] = secrets.token_hex(64)
        return env

    def build(self) -> None:
        """Assemble the app, install real dependencies, migrate a real
        per-run SQLite database, and boot ``bin/rails server``. Raises
        :class:`RailsLiveBootError` naming the failing step's real
        stdout/stderr on any failure -- never swallowed."""
        self._tmp = tempfile.TemporaryDirectory(prefix="fuzzlab-ruby-rails-live-boot-")
        self._app_dir = Path(self._tmp.name) / "app"
        self._assemble()
        env = self._harness_env()

        bundle_result = _run(
            ["bundle", "install", "--quiet"],
            cwd=self._app_dir,
            timeout=self._install_timeout,
            env=env,
        )
        if bundle_result.returncode != 0:
            raise RailsLiveBootError(
                f"bundle install failed (exit {bundle_result.returncode}):\n"
                f"{bundle_result.stdout[-4000:]}\n{bundle_result.stderr[-4000:]}"
            )

        db_result = _run(
            [str(self._app_dir / "bin" / "rails"), "db:prepare"],
            cwd=self._app_dir,
            timeout=60.0,
            env=env,
        )
        if db_result.returncode != 0:
            raise RailsLiveBootError(
                f"bin/rails db:prepare failed (exit {db_result.returncode}):\n"
                f"{db_result.stdout}\n{db_result.stderr}"
            )

        self._port = _find_free_port()
        self._proc = subprocess.Popen(
            [str(self._app_dir / "bin" / "rails"), "server", "-b", "127.0.0.1", "-p", str(self._port)],
            cwd=self._app_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        self._wait_for_boot()

    def _wait_for_boot(self) -> None:
        assert self._port is not None
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                out = self._proc.stdout.read() if self._proc.stdout else ""
                raise RailsLiveBootError(f"bin/rails server exited early (code {self._proc.returncode}):\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", self._port), timeout=1.0):
                    return
            except OSError as exc:
                last_err = exc
                time.sleep(0.25)
        raise RailsLiveBootError(f"bin/rails server did not accept connections within {BOOT_TIMEOUT_S}s: {last_err}")

    # -- HTTP -----------------------------------------------------------------

    def _base_url(self) -> str:
        assert self._port is not None
        return f"http://127.0.0.1:{self._port}"

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """A real HTTP request against the booted app, via the standard
        library only (no new HTTP client abstraction) -- mirrors
        ``LiveBootHarness.request`` exactly, including never following a
        redirect (``BUG-0028``'s lesson, applied here from the start).

        ``raw_body``/``headers`` (CC-LAB-0072, webhook-signature) let a
        caller send exact, unencoded bytes with caller-chosen headers --
        e.g. a real ``X-Shopify-Hmac-SHA256`` header computed over the
        exact bytes about to be sent, which ``data``'s own
        ``application/x-www-form-urlencoded`` encoding would otherwise
        silently re-encode out from under a caller trying to forge one.
        Mutually exclusive with ``data`` -- a caller sends one request body
        shape, never both encoded onto the same request."""
        import urllib.parse

        if raw_body is not None and data is not None:
            raise ValueError("RailsLiveBootHarness.request: pass raw_body or data, never both")

        url = self._base_url() + path
        body: bytes | None = raw_body
        request_headers: dict[str, str] = dict(headers) if headers else {}
        if params:
            url += "?" + urllib.parse.urlencode(params)
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=request_headers)
        with _NO_REDIRECT_OPENER.open(req, timeout=REQUEST_TIMEOUT_S) as resp:
            return HttpResponse(status=resp.status, body=resp.read().decode("utf-8", errors="replace"))

    def get(self, path: str, *, params: dict[str, str] | None = None) -> HttpResponse:
        return self.request("GET", path, params=params)

    def post(
        self,
        path: str,
        *,
        data: dict[str, str] | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("POST", path, data=data, raw_body=raw_body, headers=headers)

    def patch(
        self,
        path: str,
        *,
        data: dict[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("PATCH", path, data=data)

    def run_ruby(self, code: str, *, timeout: float = 30.0) -> subprocess.CompletedProcess:
        """Run a real, standalone Ruby script (``bundle exec ruby``) inside
        this harness's already-``bundle install``-ed app directory --
        CC-LAB-0072's webhook-signature timing microbenchmark uses this to
        exercise the exact real ``ActiveSupport::SecurityUtils.secure_compare``
        this app's own ``Gemfile.lock`` resolved, without a second, separate
        ``bundle install`` round trip. Must be called after :meth:`build`
        (or inside the ``with`` block) -- raises :class:`RailsLiveBootError`
        if the app is not yet assembled/installed, the same "never silently
        proceed against a directory that is not there" discipline every
        other real subprocess step in this module follows."""
        if self._app_dir is None:
            raise RailsLiveBootError("run_ruby called before build() assembled the app")
        import uuid

        script = self._app_dir / f"tmp_probe_{uuid.uuid4().hex}.rb"
        script.write_text(code, encoding="utf-8")
        try:
            return _run(
                ["bundle", "exec", "ruby", str(script)],
                cwd=self._app_dir,
                timeout=timeout,
                env=self._harness_env(),
            )
        finally:
            script.unlink(missing_ok=True)

    # -- Tier1Client conformance -----------------------------------------------

    def fetch(self, case: Tier1Case) -> str:
        """Implements :class:`fuzzlab.labgen.conformance.tier1.Tier1Client`
        for ``ruby_rails``, mirroring ``LiveBootHarness.fetch`` exactly."""
        if case.location == "query":
            return self.get(case.path, params={case.param_name: case.payload}).body
        return self.post(case.path, data={case.param_name: case.payload}).body

    # -- lifecycle --------------------------------------------------------------

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

    def __enter__(self) -> "RailsLiveBootHarness":
        self.build()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
