"""Live-boot conformance harness for ``django`` (category 2 pilot, `CC-LAB-0090`).

Mirrors :mod:`fuzzlab.labgen.conformance.live_boot`'s ``LiveBootHarness`` for
``php_laravel`` structurally (``build()``/``_assemble()``/``request()``/
``get()``/``post()``/``query_db()``/``close()``/context-manager protocol,
the same bounded-timeout-at-every-subprocess-step discipline via ``_run()``,
and the same never-follows-a-redirect HTTP client -- reusing
``fuzzlab.labgen.conformance.live_boot._NoRedirectHttpErrorProcessor``
directly rather than reimplementing it, since that class is generic
``urllib`` plumbing with no Laravel-specific behavior). The actual boot
mechanism is new: a real ``venv`` + ``pip install django==<pinned>`` +
``manage.py migrate`` + ``manage.py runserver`` boot, never Docker/
``composer``, and Django's own built-in SQLite backend needs no separate
driver install (unlike PHP's MariaDB-for-production/SQLite-for-testing
split -- this harness does not need to port ``MariaDbServer``).

**What this proves, concretely (Phase A, one shape).** :class:`DjangoLiveBootHarness`
assembles a real Django 5.2 project (the checked-in ``SKELETON_DIR``
skeleton, overlaid with a manifest's real ``DjangoEmitter``-rendered views
+ the accumulated ``urls.py``), runs a real ``pip install``, migrates +
seeds a real per-run SQLite database, boots a real ``manage.py runserver``
process (forced to ``127.0.0.1``, independent of ``DJANGO_STACK_ENV.
entrypoint_cmd``'s nominal ``0.0.0.0`` string -- ``CLAUDE.md``'s
non-negotiable Safety section), and lets a caller make real HTTP requests
against it -- proving the one illustrative ``sqli``/``sql_numeric_literal``
shape's vulnerable/secure payload differential end to end, the same bar
``php_laravel``'s and ``node_express``'s own first live-boot tests set.

**Skip-guarded, matching this project's PA-0005/PA-0035 convention.**
:func:`django_boot_available` is the one authoritative capability probe
(``python3``/``pip`` on PATH, the skeleton directory present, and a real,
bounded ``pip download django==<pinned> --no-deps`` round trip through
whatever proxy is configured -- never a bare socket/DNS check standing in
for it, exactly the class of mistake ``BUG-0033`` was for ``composer``, now
avoided from day one for ``pip`` too).

**Django/ORM defaults this harness's real boot exercises** (enumerated up
front per `CC-LAB-0090`'s pre-change review, reviewer #2, citing
`PA-0030`/`BUG-0028`'s "enumerate framework/ORM defaults before extending
this harness family" rule) -- see
``fuzzlab/labgen/emitters/django/stack/README.md``'s own section on this;
not restated here.
"""

from __future__ import annotations

import hashlib
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from fuzzlab.labgen.conformance.live_boot import (
    _NO_REDIRECT_OPENER,
    HttpResponse,
    LiveBootError,
)
from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.emitters.django.stack_env import settings_py_content
from fuzzlab.labgen.schema import Cell

#: The checked-in, trimmed real Django 5.2 project skeleton (``django-admin
#: startproject``, everything a bootable app does not need at boot time
#: stripped -- see this directory's sibling
#: ``fuzzlab/labgen/emitters/django/stack/README.md`` for the exact
#: provenance and trim list). Same "framework skeleton, reusable stack-wide"
#: half of ``StackEnv``'s own scaffold convention that ``SKELETON_DIR``
#: already means for ``php_laravel``.
SKELETON_DIR = Path(__file__).resolve().parent.parent / "emitters" / "django" / "stack" / "skeleton"

#: The exact, resolved Django release this harness installs -- matches
#: ``fuzzlab.labgen.emitters.django.stack_env.DJANGO_STACK_ENV.framework_version``.
#: A module-level constant (not re-imported from ``StackEnv``, which is
#: deliberately just data) so a caller changing the pin only has to change
#: it in one obviously-load-bearing place if the two ever need to diverge
#: -- they should not, and a mismatch here is a real authoring bug, not a
#: supported configuration.
DJANGO_PIN = "django==5.2.17"

#: How long to wait for ``manage.py runserver`` to accept connections before
#: giving up and reporting a boot failure, rather than hanging indefinitely.
BOOT_TIMEOUT_S = 30.0

#: How long a single HTTP request against the booted app may take before this
#: harness treats it as a hung/broken response rather than waiting forever.
REQUEST_TIMEOUT_S = 15.0

#: How long :func:`_pip_network_probe` may take before it reports the
#: network unavailable rather than hang -- enforced by ``subprocess.run``'s
#: own ``timeout``, mirroring ``live_boot.py``'s
#: ``NETWORK_PROBE_TIMEOUT_S``/``BUG-0033`` discipline for ``pip`` instead
#: of ``composer``.
NETWORK_PROBE_TIMEOUT_S = 30.0


def _pip_network_probe(timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Actually attempt the real operation :func:`django_boot_available`
    must predict the outcome of -- a real, bounded ``pip download
    django==<pinned> --no-deps`` round trip against the real PyPI index
    through **pip's own HTTP client** (which honors ``HTTPS_PROXY``/
    ``https_proxy`` exactly as ``pip install`` will), instead of a bare
    socket/DNS check that would not predict whether a real ``pip install``
    completes in bounded time through this environment's actual proxied
    egress path -- the same ``BUG-0033``/`PA-0035` reasoning
    ``live_boot.py``'s own ``_composer_network_probe`` docstring gives for
    ``composer``, generalized here to ``pip``.

    Downloads into a scratch directory (never this repo's own state) and
    discards it -- a read-only capability check, like every other
    ``*_available()`` probe in this project (PA-0005/PA-0008). Bounded and
    enforced by this function's own ``timeout``: a
    :class:`subprocess.TimeoutExpired` or any other failure to run ``pip``
    reports unavailable (``False``), never propagates and never hangs the
    caller (PA-0025's fail-closed doctrine)."""
    if shutil.which("pip") is None and shutil.which("pip3") is None:
        return False
    pip_cmd = shutil.which("pip3") or shutil.which("pip")
    with tempfile.TemporaryDirectory(prefix="fuzzlab-django-network-probe-") as scratch:
        try:
            result = subprocess.run(
                [pip_cmd, "download", DJANGO_PIN, "--no-deps", "-d", scratch],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
    return result.returncode == 0


def django_boot_available() -> bool:
    """The authoritative capability probe this module's own tests (and any
    other caller) must gate on before constructing a
    :class:`DjangoLiveBootHarness` -- PA-0005/PA-0008/`PA-0035`: a real
    capability check (``python3`` on PATH, the skeleton present, ``venv``
    module importable, and a real, bounded, pip-driven PyPI round trip --
    :func:`_pip_network_probe`, not a raw socket connect)."""
    if shutil.which(sys.executable or "python3") is None:
        return False
    try:
        import venv as _venv  # noqa: F401 - availability check only

        del _venv
    except ImportError:
        return False
    return SKELETON_DIR.is_dir() and _pip_network_probe()


def _run(cmd: list[str], *, cwd: Path, timeout: float, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run a real subprocess step of the live-boot pipeline (``pip
    install``, ``manage.py migrate``, ...) with an enforced, bounded
    ``timeout`` on every call site -- mirrors ``live_boot.py``'s own
    ``_run()`` byte-for-byte in shape (`PA-0035`: a passing capability probe
    is not a substitute for every *later* real subprocess operation also
    being bounded on its own)."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiveBootError(
            f"{cmd[0]} did not complete within {timeout}s (cmd={cmd!r}): "
            f"stdout={exc.stdout!r} stderr={exc.stderr!r}"
        ) from exc


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_SEED_PRODUCTS_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);
INSERT INTO products (id, name) VALUES
    (1, 'Chew Toy'),
    (2, 'Puppy Bed');
"""

#: A real users row backing the `sql_string_literal` login shape
#: (`CC-LAB-0091`) -- `password` is stored MD5-hashed, matching the
#: generated sink's own `hashlib.md5(...)` choice (kept consistent with
#: `node_express`'s identical illustrative-shape choice, not picked as a
#: stronger hash here -- both stacks prove the same SQLi differential, not
#: a hashing-strength lesson).
SEED_USERNAME = "alice"
SEED_PASSWORD = "correct-horse-battery-staple"

#: A real, default profile `bio` row backing the `read_stored_field`
#: source's `_read_stored_bio()` helper (`CC-LAB-0091`) -- a benign default;
#: a caller proving the stored-XSS differential passes an adversarial
#: `seed_bio` to the constructor instead (see `DjangoLiveBootHarness.__init__`).
DEFAULT_SEED_BIO = "Hi, I'm a happy customer!"

#: PicTrail's real `/post` detail page (`CC-LAB-0092`, Phase C) -- a
#: distinct `posts` table, not a reuse of `products` above, per that
#: entry's own "thematically-accurate table" note.
_SEED_POSTS_SQL = """
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);
INSERT INTO posts (id, name) VALUES
    (1, 'A walk in the park'),
    (2, 'Sunset over the lake');
"""

#: A real, default comment `body` row backing the `/post/comments` page's
#: `_read_stored_comment()` helper (`CC-LAB-0093`) -- a benign default; a
#: caller proving the `mark_safe()` differential passes an adversarial
#: `seed_comment` to the constructor instead, mirroring `seed_bio`'s own
#: convention exactly.
DEFAULT_SEED_COMMENT = "Great shot! Love the lighting."


class DjangoLiveBootHarness:
    """Assembles, installs, migrates, and boots one manifest's ``django``
    build for real, and serves real HTTP requests against it.

    Use as a context manager::

        with DjangoLiveBootHarness(emitter, cells) as harness:
            resp = harness.get("/generated/labgen_dj_0001/", params={"id": "1"})

    Every temp directory and the ``manage.py runserver`` process it starts
    are cleaned up on ``__exit__`` -- including when an exception
    propagates, mirroring ``LiveBootHarness``'s own PA-0012 teardown
    discipline.
    """

    def __init__(
        self,
        emitter: Emitter,
        cells: list[Cell],
        *,
        install_timeout: float = 180.0,
        seed_bio: str = DEFAULT_SEED_BIO,
        seed_comment: str = DEFAULT_SEED_COMMENT,
    ) -> None:
        """``seed_bio`` (`CC-LAB-0091`): the value seeded into the
        `read_stored_field` source's backing `profiles` row. A caller
        proving the stored-XSS differential passes an adversarial payload
        here (e.g. ``"<script>alert(1)</script>"``) -- the default is a
        benign value so a caller not exercising that shape gets ordinary
        content. ``seed_comment`` (`CC-LAB-0093`): the same convention for
        the `/post/comments` page's backing `comments` row."""
        self._emitter = emitter
        self._cells = [c for c in cells if emitter.supports(c.vuln_class, c.sink_context)]
        self._install_timeout = install_timeout
        self._seed_bio = seed_bio
        self._seed_comment = seed_comment
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._app_dir: Path | None = None
        self._venv_dir: Path | None = None
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None

    # -- assembly ------------------------------------------------------------

    def _assemble(self) -> None:
        assert self._app_dir is not None
        shutil.copytree(SKELETON_DIR, self._app_dir, dirs_exist_ok=True)

        for cell in self._cells:
            for emitted in self._emitter.render(cell):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)

        accumulator_file = self._emitter.render_route_accumulator(self._cells)
        dest = self._app_dir / accumulator_file.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(accumulator_file.content)

        settings_dest = self._app_dir / "fuzlab_django_lab" / "settings.py"
        settings_dest.write_bytes(settings_py_content())

    def _venv_python(self) -> Path:
        assert self._venv_dir is not None
        return self._venv_dir / "bin" / "python"

    def _seed_db(self) -> None:
        assert self._app_dir is not None
        db_path = self._app_dir / "db.sqlite3"
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(_SEED_PRODUCTS_SQL)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
                (1, SEED_USERNAME, hashlib.md5(SEED_PASSWORD.encode("utf-8")).hexdigest()),
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY, bio TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO profiles (id, bio) VALUES (1, ?)", (self._seed_bio,))
            conn.executescript(_SEED_POSTS_SQL)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, body TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO comments (id, body) VALUES (1, ?)", (self._seed_comment,))
            conn.commit()
        finally:
            conn.close()

    def query_db(self, sql: str, params: tuple = ()) -> list[dict]:
        """Read-only introspection over the harness's own seeded SQLite
        database -- same purpose as ``LiveBootHarness.query_db``: a test
        observing state without this harness growing a second,
        HTTP-response-parsing mechanism for something a direct row read
        answers more simply."""
        assert self._app_dir is not None
        db_path = self._app_dir / "db.sqlite3"
        conn = sqlite3.connect(db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def build(self) -> None:
        """Assemble the app, create a real ``venv``, install a real
        ``django==<pinned>``, migrate + seed the database, and boot
        ``manage.py runserver`` bound to ``127.0.0.1`` (forced,
        independent of ``DJANGO_STACK_ENV.entrypoint_cmd``'s nominal
        ``0.0.0.0`` string -- ``CLAUDE.md``'s non-negotiable Safety
        section). Raises :class:`LiveBootError` naming the failing step's
        real stdout/stderr on any failure -- never swallowed, mirroring
        ``LiveBootHarness.build()``'s fail-loud convention."""
        self._tmp = tempfile.TemporaryDirectory(prefix="fuzzlab-django-live-boot-")
        self._app_dir = Path(self._tmp.name) / "app"
        self._venv_dir = Path(self._tmp.name) / "venv"
        self._assemble()

        venv_result = _run(
            [sys.executable, "-m", "venv", str(self._venv_dir)],
            cwd=Path(self._tmp.name),
            timeout=60.0,
        )
        if venv_result.returncode != 0:
            raise LiveBootError(
                f"python -m venv failed (exit {venv_result.returncode}):\n"
                f"{venv_result.stdout}\n{venv_result.stderr}"
            )

        pip_result = _run(
            [str(self._venv_dir / "bin" / "pip"), "install", "-q", DJANGO_PIN],
            cwd=self._app_dir,
            timeout=self._install_timeout,
        )
        if pip_result.returncode != 0:
            raise LiveBootError(
                f"pip install {DJANGO_PIN} failed (exit {pip_result.returncode}):\n"
                f"{pip_result.stdout[-4000:]}\n{pip_result.stderr[-4000:]}"
            )

        migrate_result = _run(
            [str(self._venv_python()), "manage.py", "migrate", "--no-input"],
            cwd=self._app_dir,
            timeout=60.0,
        )
        if migrate_result.returncode != 0:
            raise LiveBootError(
                f"manage.py migrate failed (exit {migrate_result.returncode}):\n"
                f"{migrate_result.stdout}\n{migrate_result.stderr}"
            )

        self._seed_db()

        self._port = _find_free_port()
        self._proc = subprocess.Popen(
            [str(self._venv_python()), "manage.py", "runserver", f"127.0.0.1:{self._port}", "--noreload"],
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
                raise LiveBootError(f"manage.py runserver exited early (code {self._proc.returncode}):\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", self._port), timeout=1.0):
                    return
            except OSError as exc:
                last_err = exc
                time.sleep(0.25)
        raise LiveBootError(f"manage.py runserver did not accept connections within {BOOT_TIMEOUT_S}s: {last_err}")

    # -- HTTP ------------------------------------------------------------------

    def _base_url(self) -> str:
        assert self._port is not None
        return f"http://127.0.0.1:{self._port}"

    def request(self, method: str, path: str, *, params: dict[str, str] | None = None,
                data: dict[str, str] | None = None) -> HttpResponse:
        """A real HTTP request against the booted app. Reuses
        ``live_boot.py``'s shared, never-follows-a-redirect opener
        (``_NO_REDIRECT_OPENER`` -- ``BUG-0028``) directly rather than
        reimplementing it: that opener is generic ``urllib`` plumbing with
        no Laravel-specific behavior, so importing it keeps exactly one
        no-redirect policy in this codebase instead of two that could
        drift apart."""
        url = self._base_url() + path
        body: bytes | None = None
        headers = {}
        if params:
            url += "?" + urllib.parse.urlencode(params)
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
        with _NO_REDIRECT_OPENER.open(req, timeout=REQUEST_TIMEOUT_S) as resp:
            return HttpResponse(status=resp.status, body=resp.read().decode("utf-8", errors="replace"))

    def get(self, path: str, *, params: dict[str, str] | None = None) -> HttpResponse:
        return self.request("GET", path, params=params)

    def post(self, path: str, *, data: dict[str, str] | None = None) -> HttpResponse:
        return self.request("POST", path, data=data)

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

    def __enter__(self) -> "DjangoLiveBootHarness":
        self.build()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
