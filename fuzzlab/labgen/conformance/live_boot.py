"""Live-boot conformance harness for ``php_laravel`` (T-LAB0.7 Tier 1/2 --
``docs/LAB_IMPLEMENTATION_PLAN.md`` ~line 154, ``CC-LAB-0054``/``FR-LAB-52``).

Everything in :mod:`fuzzlab.labgen.conformance.tier1`/``tier2`` is, by its own
module docstring, a **design-only interface**: no test in this repo has ever
actually installed, booted, or sent a real HTTP request to a
``php_laravel``-emitted app. This module is the first real implementation of
that missing "on-host last-mile" -- but built to run entirely inside this
project's own offline test suite, using PHP's built-in development server
and a per-run SQLite database instead of the production MariaDB target
(``lab/sql/schema.sql``) and Docker (never touched here; see the module
docstring below for why SQLite is a **test-harness-only** substitution, not
a production choice).

**What this proves, concretely.** :class:`LiveBootHarness` assembles a real
Laravel 13 project (the checked-in :data:`SKELETON_DIR` skeleton, overlaid
with a manifest's real ``LaravelEmitter``-rendered controllers/views/routes),
runs a real ``composer install --no-dev``, migrates + seeds a real SQLite
database, boots a real ``php artisan serve`` process, and lets a caller make
real ``requests`` calls against it. :func:`Tier1Client`-conformant --
:meth:`LiveBootHarness.fetch` implements
:class:`fuzzlab.labgen.conformance.tier1.Tier1Client`, so a
:class:`~fuzzlab.labgen.conformance.tier1.Tier1Case` can be run against a
*real* client for the first time, not just a hand-written test double.

**Coverage (``CC-LAB-0056``/``FR-LAB-54``, extending ``CC-LAB-0054``/
``FR-LAB-52``).** Five of the six ``phase3_php_laravel_real_pages_*``/
``phase3_laravel_real_pages_*`` manifests are now driven end to end:
``forms`` and ``numeric`` (``CC-LAB-0054``), plus ``auth`` (``login.php``'s
real SQLi-bypass/bound-parameter twin against a real seeded ``users`` row,
and ``register.php``'s real prepared ``INSERT``), ``g2`` (``products.php`` /
``api/products.php``'s real JSON feed), and ``g4`` (the
``edit_profile.php`` -> ``profile.php`` stored-second-order write-then-read
round trip) (``CC-LAB-0056``). ``search.php`` remains genuinely unpinned
(no single cell owns its real URL yet, pending the ``L-P3.3c-CUT`` decision
-- see that manifest's own header) and is not attempted here.

**The seeded ``users`` row (:data:`SEED_USERNAME`/:data:`SEED_PASSWORD`,
user id :data:`SEED_USER_ID`).** One row serves both the auth group's real
login and the G4 group's stored-``bio`` owner default (``$request->query
('user', 1)``) -- the same real ``users`` table both groups' migrated pages
read, not two independently-seeded rows for what is one table. Its password
is stored **md5-hashed**, matching ``login.php``'s own
``password_hash_fn`` (see ``php_laravel.__init__._PAGE_PROFILES
['/login.php']``) -- never bcrypt/``Hash::make``: the migrated
login/register controllers go through ``DB::table('users')`` (the query
builder), never Eloquent, so ``App\\Models\\User``'s ``'password' =>
'hashed'`` cast (which *would* expect bcrypt) is never invoked for either
page. Confirmed directly against the skeleton's own ``app/Models/User.php``
before relying on it, not assumed.

**Why SQLite here, MariaDB in the real lab.** Per this task's own scope: the
production lab target (``puppy-fort-factory/`` today, this generator's output
after the eventual ``L-P3.3c-CUT`` atomic cutover) is deliberately MariaDB,
matching ``lab/sql/schema.sql`` -- identifier-position SQL injection can
behave differently across SQL dialects (this is exactly why
``tier1.py``'s own docstring calls an in-memory-SQLite substitute unsound for
*that* purpose). This module never claims to replace that: it does not
confirm an oracle-grade vulnerable/secure verdict (that remains Tier 2's,
genuinely out of scope until a real containerized oracle exists), it proves
the strictly narrower, but previously entirely unproven, claim that a
``php_laravel``-emitted build actually **boots and serves** its pinned real
URLs and that a payload differential is **observable** end to end -- a
necessary precondition for ``L-P3.3c-CUT``, not a substitute for its own
parity gate. SQLite is adequate for that narrower claim because none of the
manifests this module currently drives (the numeric-literal and
escaped-echo-form real-page groups) touch identifier/alias-position SQL --
the one shape class where dialect matters for the *verdict itself*.

**Skip-guarded, matching this project's PA-0005/T-LAB0.7 convention.**
:func:`live_boot_available` is the one authoritative capability probe
(``composer`` + ``php`` on PATH, plus real Packagist network reachability) a
caller (chiefly the pytest suite) must check before constructing a
:class:`LiveBootHarness` -- exactly like :func:`tier0.php_available` gates
``php -l``. A missing tool or unreachable network SKIPS the check; it never
silently reports a pass.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from fuzzlab.labgen.conformance.tier1 import Tier1Case
from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.schema import Cell

#: The checked-in, trimmed real Laravel 13 project skeleton (``composer
#: create-project laravel/laravel``, dev-only tooling and the front-end build
#: pipeline stripped -- see this directory's sibling ``README.md`` for the
#: exact provenance and trim list). This is the "framework skeleton, reusable
#: stack-wide" half of ``StackEnv``'s own scaffold convention
#: (``stack_env.py``'s ``scaffold_files``/``render_scaffold`` docstring); the
#: "generated per-manifest content" half is whatever a real
#: ``LaravelEmitter`` build renders on top of it, exactly as it does for every
#: other conformance tier.
SKELETON_DIR = Path(__file__).resolve().parent.parent / "emitters" / "php_laravel" / "stack" / "skeleton"

#: How long to wait for ``php artisan serve`` to accept connections before
#: giving up and reporting a boot failure, rather than hanging indefinitely.
BOOT_TIMEOUT_S = 30.0

#: How long a single HTTP request against the booted app may take before this
#: harness treats it as a hung/broken response rather than waiting forever.
REQUEST_TIMEOUT_S = 15.0


class LiveBootError(RuntimeError):
    """Raised when assembling, installing, migrating, or booting the app
    fails for a reason that is not "the environment lacks composer/network"
    (that case is :func:`live_boot_available` returning ``False``, a skip,
    never an error)."""


def _network_reachable(host: str = "repo.packagist.org", timeout: float = 5.0) -> bool:
    try:
        socket.create_connection((host, 443), timeout=timeout).close()
        return True
    except OSError:
        return False


def live_boot_available() -> bool:
    """The authoritative capability probe this module's own tests (and any
    other caller) must gate on before constructing a
    :class:`LiveBootHarness` -- PA-0005/PA-0008: a real capability check
    (composer + php on PATH, and Packagist actually reachable), never a
    fragile proxy. Composer's own dry-run resolution against Packagist is
    what this project's task brief verified by hand; this is that same
    check, made mechanical and skip-guarding rather than assumed once and
    hardcoded."""
    return (
        shutil.which("composer") is not None
        and shutil.which("php") is not None
        and SKELETON_DIR.is_dir()
        and _network_reachable()
    )


class _NoRedirectHttpErrorProcessor(urllib.request.HTTPErrorProcessor):
    """Hands back every response -- 2xx, 3xx, 4xx, 5xx alike -- exactly as
    the server sent it, instead of ``urllib``'s default behavior of raising
    :class:`urllib.error.HTTPError` for non-2xx and silently *following* a
    3xx via :class:`urllib.request.HTTPRedirectHandler` (``BUG-0028``: this
    harness must observe the raw redirect, never chase it)."""

    def http_response(self, request, response):  # noqa: D102 - stdlib override
        return response

    https_response = http_response


#: One shared, never-follows-a-redirect opener for every
#: :meth:`LiveBootHarness.request` call -- built once at import time (it
#: holds no per-app state) rather than per request.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHttpErrorProcessor())


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


#: A harness-only ``.env`` -- SQLite, debug off (matches
#: ``StackEnv.env_file_content()``'s own security requirement; see that
#: method's docstring for why ``APP_DEBUG=false`` is load-bearing even here),
#: file-backed session/cache so no extra service is needed. Deliberately NOT
#: ``StackEnv.env_file_content()`` itself: that method's ``DB_CONNECTION=mysql``
#: is the real lab's own production default (matching ``lab/compose.yaml``),
#: and this harness must not silently diverge production config by editing
#: that shared method -- see the module docstring for the SQLite-is-a-test-
#: harness-detail rationale.
def _harness_env_content(*, app_key: str) -> bytes:
    lines = (
        "APP_NAME=FuzzlabPhpLaravelLiveBootHarness",
        "APP_ENV=testing",
        f"APP_KEY={app_key}",
        "APP_DEBUG=false",
        "APP_URL=http://127.0.0.1",
        "",
        "LOG_CHANNEL=stack",
        "LOG_LEVEL=error",
        "",
        "DB_CONNECTION=sqlite",
        "DB_DATABASE=" + "/__DB_PATH__",
        "",
        "SESSION_DRIVER=file",
        "CACHE_STORE=file",
        "",
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


#: Minimal SQLite schema covering exactly the tables the currently-driven
#: real-page manifests' rendered controllers touch (``products``, ``posts``,
#: ``users``) -- **not** a port of ``puppy-fort-factory/sql/schema.sql``
#: (read for shape only, per this task's instructions; that file is not
#: touched or moved). Widen this alongside whichever new manifest a future
#: extension of :data:`DRIVABLE_MANIFEST_TABLES` needs.
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    category TEXT NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT,
    bio TEXT,
    created_at TEXT,
    updated_at TEXT
);
"""
#: ``created_at``/``updated_at`` above are for :class:`\\App\\Models\\User`
#: alone (``login.php``/``register.php`` go through ``DB::table('users')``,
#: which never touches them): Eloquent's default ``$timestamps = true``
#: unconditionally sets ``updated_at`` on every ``->save()`` -- including the
#: G4 write endpoint's ``$storedOwner->save()`` -- regardless of whether the
#: real reproduced page tracks timestamps, so the seeded table must have
#: somewhere for Eloquent to put it or every G4 write 500s
#: (``SQLSTATE[HY000]: no such column: updated_at`` -- ``BUG-0028``).

#: The auth-group real login (``LABGEN-PLA-0001``/``0002``) and stored
#: second-order (``LABGEN-PLRP-0401``/``0402``) manifests both need a real,
#: pre-existing ``users`` row: ``id=1`` is the ``owner_param`` default every
#: ``/profile.php``/``/edit_profile.php`` request falls back to
#: (``read_stored_field.php.j2``/``stored_field_write.php.j2``:
#: ``$request->query('user', 1)``), and it is also this harness's one known
#: login identity for ``/login.php`` -- the same row serves both groups
#: (``CC-LAB-0056``/``FR-LAB-54``), never two independently-seeded rows for
#: what is the same real page's one users table.
#:
#: The password is stored **md5-hashed**, matching the real page's own
#: ``password_hash_fn`` (``php_laravel.__init__._PAGE_PROFILES['/login.php']``)
#: -- never bcrypt/``Hash::make``, which the migrated login controller does
#: not call (it goes through ``DB::table('users')``, not Eloquent, so the
#: model's ``'password' => 'hashed'`` cast is never in play for login/register
#: -- see this harness's own test module for the full reasoning).
SEED_USER_ID = 1
SEED_USERNAME = "user_a"
SEED_PASSWORD = "correct-horse-battery-staple"
SEED_EMAIL = "user_a@example.test"
SEED_FULL_NAME = "User A"
SEED_BIO = "Just a puppy fan."


def _seed_password_hash() -> str:
    import hashlib

    return hashlib.md5(SEED_PASSWORD.encode("utf-8")).hexdigest()


_SEED_SQL = """
INSERT INTO products (name, description, price, category, stock) VALUES
    ('Chew Toy', 'A rugged rope toy', 9.99, 'toys', 42),
    ('Puppy Bed', 'Memory foam bed', 39.99, 'beds', 7);
INSERT INTO posts (title, body) VALUES
    ('Welcome to the Fort', 'Our very first blog post.');
"""


def _run(cmd: list[str], *, cwd: Path, timeout: float, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env,
    )
    return result


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str


class LiveBootHarness:
    """Assembles, installs, migrates, and boots one manifest's
    ``php_laravel`` build for real, and serves real HTTP requests against it.

    Use as a context manager:

        with LiveBootHarness(emitter, cells) as harness:
            resp = harness.get("/product.php", params={"id": "1"})

    Every temp directory and the ``php artisan serve`` process it starts are
    cleaned up on ``__exit__`` -- including when an exception propagates
    (PA-0012's "bounded, deterministic teardown" rule, applied here to a
    subprocess rather than an asyncio server).
    """

    def __init__(self, emitter: Emitter, cells: list[Cell], *, install_timeout: float = 240.0) -> None:
        self._emitter = emitter
        self._cells = [c for c in cells if emitter.supports(c.vuln_class, c.sink_context)]
        self._install_timeout = install_timeout
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._app_dir: Path | None = None
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None

    # -- assembly ----------------------------------------------------------

    def _assemble(self) -> None:
        assert self._app_dir is not None
        shutil.copytree(SKELETON_DIR, self._app_dir, dirs_exist_ok=True)

        # Per-manifest generated content: every supported cell's controllers/
        # views/resources, plus the accumulated routes/web.php -- the two
        # things fuzzlab.labgen.cli.render_manifest does NOT currently
        # assemble (it renders per-cell EmittedFiles only; scaffold files and
        # the route accumulator are each a separate, documented step no
        # existing CLI path drives end to end). This is that missing
        # assembly step, built here because proving a real boot is exactly
        # what needed it built for real.
        fragments: dict[str, str] = {}
        for cell in self._cells:
            for emitted in self._emitter.render(cell):
                dest = self._app_dir / emitted.path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(emitted.content)
            fragments[cell.cell_id] = self._emitter.route_fragment_for(cell)

        from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator

        routes_file = self._app_dir / "routes" / "web.php"
        routes_file.write_text(RouteAccumulator().render_file(fragments), encoding="utf-8")

    def _write_env(self) -> None:
        assert self._app_dir is not None
        db_path = self._app_dir / "database" / "database.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.touch()
        # A real APP_KEY, not a placeholder -- `artisan key:generate` writes
        # it after install, matching a real `composer create-project` first
        # run; encryption/session signing must not run on a fixed literal.
        content = _harness_env_content(app_key="").replace(b"/__DB_PATH__", str(db_path).encode("utf-8"))
        (self._app_dir / ".env").write_bytes(content)

    def _seed_db(self) -> None:
        assert self._app_dir is not None
        db_path = self._app_dir / "database" / "database.sqlite"
        import sqlite3

        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(_SCHEMA_SQL)
            conn.executescript(_SEED_SQL)
            conn.execute(
                "INSERT INTO users (id, username, email, password, full_name, bio) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    SEED_USER_ID,
                    SEED_USERNAME,
                    SEED_EMAIL,
                    _seed_password_hash(),
                    SEED_FULL_NAME,
                    SEED_BIO,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def query_db(self, sql: str, params: tuple = ()) -> list[dict]:
        """Read-only introspection over the harness's own seeded SQLite
        database, for a test to observe a write it made through a real HTTP
        request (e.g. ``register.php``'s real ``INSERT``) without this
        harness growing a second, parallel HTTP-response-parsing mechanism
        for something a direct row read answers more simply. Never used by
        this module itself to *drive* a request -- only by a caller
        confirming one already landed."""
        assert self._app_dir is not None
        import sqlite3

        db_path = self._app_dir / "database" / "database.sqlite"
        conn = sqlite3.connect(db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def build(self) -> None:
        """Assemble the app, install real dependencies, seed the database,
        and boot ``php artisan serve``. Raises :class:`LiveBootError` naming
        the failing step's real stdout/stderr on any failure -- never
        swallowed, per this project's fail-loud convention."""
        self._tmp = tempfile.TemporaryDirectory(prefix="fuzzlab-php-laravel-live-boot-")
        self._app_dir = Path(self._tmp.name) / "app"
        self._assemble()
        self._write_env()

        composer_result = _run(
            ["composer", "install", "--no-dev", "--no-interaction", "--no-progress", "--prefer-dist"],
            cwd=self._app_dir,
            timeout=self._install_timeout,
        )
        if composer_result.returncode != 0:
            raise LiveBootError(
                f"composer install failed (exit {composer_result.returncode}):\n"
                f"{composer_result.stdout[-4000:]}\n{composer_result.stderr[-4000:]}"
            )

        key_result = _run(["php", "artisan", "key:generate", "--force"], cwd=self._app_dir, timeout=30.0)
        if key_result.returncode != 0:
            raise LiveBootError(f"artisan key:generate failed:\n{key_result.stdout}\n{key_result.stderr}")

        self._seed_db()

        self._port = _find_free_port()
        self._proc = subprocess.Popen(
            ["php", "artisan", "serve", "--host=127.0.0.1", f"--port={self._port}"],
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
                raise LiveBootError(f"php artisan serve exited early (code {self._proc.returncode}):\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", self._port), timeout=1.0):
                    return
            except OSError as exc:
                last_err = exc
                time.sleep(0.25)
        raise LiveBootError(f"php artisan serve did not accept connections within {BOOT_TIMEOUT_S}s: {last_err}")

    # -- HTTP ---------------------------------------------------------------

    def _base_url(self) -> str:
        assert self._port is not None
        return f"http://127.0.0.1:{self._port}"

    def request(self, method: str, path: str, *, params: dict[str, str] | None = None,
                data: dict[str, str] | None = None) -> HttpResponse:
        """A real HTTP request against the booted app. Uses only the standard
        library (``urllib``) so this module needs no extra runtime
        dependency beyond what :mod:`fuzzlab` already declares.

        Never follows a redirect (``BUG-0028``): a real login/session page
        (``/login.php``) and a stored-second-order write endpoint
        (``/edit_profile.php``) both legitimately respond with a real
        ``302``, and a caller proving *that specific* response -- not
        whatever page it happens to point at -- needs the raw status and
        body this app actually returned. ``urllib``'s default opener
        auto-follows a ``301``/``302``/``303`` for a ``POST`` too (converting
        it to a ``GET`` on the new URL, per :class:`urllib.request.
        HTTPRedirectHandler.redirect_request`'s own docstring) -- exactly the
        stdlib default this method must not inherit here, or a real
        auth-bypass 302 silently turns into whatever the redirect target
        happens to return instead (see ``BUG-0028`` for the concrete case
        this masked)."""
        import urllib.parse

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

    # -- Tier1Client conformance ---------------------------------------------

    def fetch(self, case: Tier1Case) -> str:
        """Implements :class:`fuzzlab.labgen.conformance.tier1.Tier1Client`
        for real -- the first real client that protocol has ever had. A
        query-location case sends ``payload`` as ``case.param_name``'s query
        value; a body-location case sends it as a form field."""
        if case.location == "query":
            return self.get(case.path, params={case.param_name: case.payload}).body
        return self.post(case.path, data={case.param_name: case.payload}).body

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

    def __enter__(self) -> "LiveBootHarness":
        self.build()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
