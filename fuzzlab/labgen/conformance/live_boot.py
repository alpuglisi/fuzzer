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
round trip) (``CC-LAB-0056``). ``search.php`` was the sixth, genuinely
unpinned page (no single cell owned its real URL, pending the
``L-P3.3c-CUT`` decision); ``CC-LAB-0058``/``FR-LAB-55`` resolved that
decision (``LABGEN-PL-RP-0001`` canonical, ``PFF-0003`` exempted -- see
``fuzzlab.labgen.emitters.php_laravel._PAGE_PROFILES['/search.php']``) and
this module's MariaDB-backed mode below now live-boots it too, real HTTP
proof included. **L-P3.3c-DOM** (``CC-LAB-0066``) adds a seventh manifest,
``dom`` (``reviews.php``/``feedback.php``, ``PFF-0007``/``PFF-0008``): the
one manifest live-booted here with no server-side round trip to
differentiate on at all -- the read and the write both happen inside the
generated page's own ``<script>`` block, so the proof is that the real,
pinned URL serves and embeds the right client-side shape (``innerHTML`` vs.
``textContent``), not a payload differential.

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
production lab target (the generator's own output, per ``L-P3.3c-CUT`` --
the hand-built ``puppy-fort-factory/`` this replaced) is deliberately MariaDB,
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
(``composer`` + ``php`` on PATH, plus a real, bounded Packagist round trip
made through composer's own HTTP client -- ``BUG-0033``: a bare raw-socket
reachability check is not an accurate predictor of whether a real
``composer install`` will complete in bounded time, e.g. when this
environment's real HTTPS path requires a configured proxy a raw
``socket.create_connection`` bypasses) a caller (chiefly the pytest suite)
must check before constructing a :class:`LiveBootHarness` -- exactly like
:func:`tier0.php_available` gates ``php -l``. A missing tool or unreachable
network SKIPS the check; it never silently reports a pass, and every later
real subprocess step in the pipeline (``composer install``, ``artisan
key:generate``) also enforces its own bounded timeout independently -- the
probe passing is never relied on alone to guarantee those won't hang.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
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


#: How long :func:`_composer_network_probe` may take before it reports the
#: network unavailable rather than hang -- enforced by ``subprocess.run``'s
#: own ``timeout``, never inferred from the probe "returning" on its own
#: (``BUG-0033``: a probe that can only report success/failure, never hang,
#: is the entire point of replacing a bare socket connect with it).
NETWORK_PROBE_TIMEOUT_S = 20.0


def _composer_network_probe(timeout: float = NETWORK_PROBE_TIMEOUT_S) -> bool:
    """Actually attempt the real operation :func:`live_boot_available` must
    predict the outcome of -- a real Packagist metadata round trip through
    **composer's own HTTP client** (``composer show -a <pkg>``, the cheapest
    composer subcommand that still performs one) -- instead of a bare
    ``socket.create_connection`` to port 443 (``BUG-0033``).

    Why the raw-socket version was wrong, concretely: in this project's own
    sandboxed CI environment, outbound HTTPS only actually completes through
    a configured HTTPS proxy (``HTTPS_PROXY``/``https_proxy``; see
    ``/root/.ccr/README.md``). A raw TCP ``connect()`` to
    ``repo.packagist.org:443`` can succeed (this environment's egress
    accepts the TCP handshake) even though a *real* TLS/HTTP request outside
    the proxied path is not the path ``composer install`` itself will use --
    so the old probe's "yes, network available" answer did not predict
    whether the real dependent operation (a real ``composer install``) would
    complete in bounded time. This probe closes that gap by running the
    *actual client* (``composer``, which honors ``HTTPS_PROXY`` exactly as
    ``composer install`` will) against the *actual dependency* (Packagist),
    not a substitute transport.

    ``psr/log`` is queried with no local ``composer.json`` present (run from
    a scratch cwd) so this never reads/writes this repo's own lockfile or
    vendor state -- a read-only capability check, like every other
    ``*_available()`` probe in this project (PA-0005/PA-0008).

    Bounded and enforced by this function's own ``timeout`` -- a
    :class:`subprocess.TimeoutExpired` or any other failure to run composer
    reports unavailable (``False``), never propagates and never hangs the
    caller: PA-0025's fail-closed doctrine ("a wrapper's status conclusion
    must be independently verified against the real thing, not inferred"),
    extended here from tool-oracle output classification to a pre-flight
    capability probe."""
    if shutil.which("composer") is None:
        return False
    try:
        result = subprocess.run(
            ["composer", "show", "-a", "--no-interaction", "--no-ansi", "psr/log"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=tempfile.gettempdir(),
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def live_boot_available() -> bool:
    """The authoritative capability probe this module's own tests (and any
    other caller) must gate on before constructing a
    :class:`LiveBootHarness` -- PA-0005/PA-0008: a real capability check
    (composer + php on PATH, and a real, bounded, composer-driven Packagist
    round trip -- :func:`_composer_network_probe`, not a raw socket connect;
    see its own docstring and ``BUG-0033`` for why the raw-socket version
    was a fragile, misleading proxy for the real thing it needed to
    predict)."""
    return (
        shutil.which("composer") is not None
        and shutil.which("php") is not None
        and SKELETON_DIR.is_dir()
        and _composer_network_probe()
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


# ---------------------------------------------------------------------------
# MariaDB-backed mode (`CC-LAB-0058`/`FR-LAB-55`)
# ---------------------------------------------------------------------------
#
# Everything above this point (and the SQLite path of :class:`LiveBootHarness`
# below) is `CC-LAB-0054`/`CC-LAB-0056`'s original, unmodified harness -- see
# the module docstring's "Why SQLite here, MariaDB in the real lab" section
# for the gap this closes: nobody had yet proven a `php_laravel`-emitted
# build against the actual database engine `lab/compose.yaml` provisions.
# This sandbox happens to carry a real, locally-installed `mariadb-server`
# (confirmed via `service mariadb start` + `mariadb-admin ping` -- not
# Docker, the bare binary), which is exactly the missing "real engine" this
# task closes the gap with.
#
# **Real schema, real seed data.** :data:`REAL_SCHEMA_SQL` is
# ``lab/sql/schema.sql`` itself, imported verbatim
# (``mariadb < schema.sql``) -- never a port or a synthetic equivalent (that
# is exactly what the SQLite path above is, and exactly what this mode
# exists to go beyond). Because that file both creates the schema AND seeds
# real rows (``admin``/``alice``/``bob``, ten real products, four real
# posts), this mode seeds nothing of its own for those tables -- it reads
# back and asserts against the *real* seeded values schema.sql already
# ships, never re-declaring a parallel seed fixture PA-0003/PA-0021 would
# flag as a second, drifting source of the same facts.
#
# **The identity matches ``lab/compose.yaml``'s own defaults, literally**
# (``PFF_DB_NAME``/``PFF_DB_USER``/``PFF_DB_PASS`` -> ``puppy_fort``/``pff``/
# ``pff_lab_pw``) -- not a made-up test-only name -- so the seam this proves
# (php_laravel output -> real MariaDB) is the same seam the real lab's own
# compose file wires, per this task's own instruction. These are the lab's
# already-public, checked-in-to-``lab/compose.yaml`` DEFAULT development
# credentials for a deliberately-vulnerable, loopback-only lab target, not a
# real secret (PA-0004/D12 govern *production* credentials, which this is
# not); nothing here is deployed or exposed.


#: ``lab/sql/schema.sql`` -- read and imported for real (re-pointed here by
#: `L-P3.3c-CUT`, `CC-LAB-0067`/`FR-LAB-62`, from the retired
#: ``puppy-fort-factory/sql/schema.sql`` -- moved, never forked, so this is
#: still the same one file, not a second copy), the actual schema/seed data
#: `lab/compose.yaml`'s `db` service provisions a fresh MariaDB from.
REAL_SCHEMA_SQL = Path(__file__).resolve().parents[3] / "lab" / "sql" / "schema.sql"

#: The identity this harness provisions on the local `mariadbd`, matching
#: `lab/compose.yaml`'s own `PFF_DB_NAME`/`PFF_DB_USER`/`PFF_DB_PASS` default
#: values (`${PFF_DB_NAME:-puppy_fort}` etc.) -- see the module-level comment
#: above for why these are the lab's own already-public dev defaults, not a
#: secret this harness invents.
MARIADB_DB_NAME = "puppy_fort"
MARIADB_DB_USER = "pff"
MARIADB_DB_PASSWORD = "pff_lab_pw"
MARIADB_HOST = "127.0.0.1"
MARIADB_PORT = 3306

#: How long to wait for a just-(re)started `mariadbd` to answer `mariadb-admin
#: ping` before giving up -- mirrors :data:`BOOT_TIMEOUT_S`'s role for `php
#: artisan serve`, applied to the other real process this mode manages.
MARIADB_BOOT_TIMEOUT_S = 30.0


def mariadb_available() -> bool:
    """The authoritative capability probe a caller (chiefly the pytest
    suite) must check before constructing a :class:`MariaDbServer` --
    PA-0005/PA-0008: a real capability check, never a fragile proxy, mirroring
    :func:`live_boot_available`'s own convention for composer/php.

    Deliberately does **not** itself start `mariadbd` (a probe must not have
    the side effects of the thing it is probing for) -- it checks that the
    real binaries and the real schema fixture this mode needs are present:
    the `mariadb`/`mariadb-admin` client binaries on PATH, the system
    `service` command and the `mariadb` init script (so this harness can
    actually start/stop a real server), and
    ``lab/sql/schema.sql`` itself. A missing tool or fixture
    SKIPS the check; it never silently reports a pass."""
    return (
        shutil.which("mariadb") is not None
        and shutil.which("mariadb-admin") is not None
        and shutil.which("service") is not None
        and Path("/etc/init.d/mariadb").is_file()
        and REAL_SCHEMA_SQL.is_file()
    )


class MariaDbServer:
    """Starts (if not already running), provisions, and tears down a real
    local `mariadbd` for one live-boot run -- via the system `service`
    command (the more reliable, already-integrated-with-this-sandbox path;
    see the module docstring), never a hand-rolled `mariadbd` invocation with
    a bespoke datadir.

    Use as a context manager:

        with MariaDbServer() as db:
            ...  # a real MariaDB is now reachable at db.host:db.port

    **Cleanup (task instruction 6), on every exit path including a raised
    exception** (PA-0012's "bounded, deterministic teardown" convention,
    applied here to a system service + a database/user rather than an
    asyncio server): the test database and user this run created are always
    dropped, and the `mariadbd` service is stopped again **only if this
    instance is the one that started it** -- a `mariadbd` this sandbox
    already had running before the test (e.g. a human's own interactive
    session) is left exactly as found, never stopped out from under them.
    """

    def __init__(
        self,
        *,
        db_name: str = MARIADB_DB_NAME,
        db_user: str = MARIADB_DB_USER,
        db_password: str = MARIADB_DB_PASSWORD,
        host: str = MARIADB_HOST,
        port: int = MARIADB_PORT,
    ) -> None:
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        self.host = host
        self.port = port
        self._we_started_service = False
        self._provisioned = False

    def _root_run(self, sql: str, *, timeout: float = 30.0) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["mariadb", "-u", "root", "-e", sql],
            capture_output=True, text=True, timeout=timeout,
        )

    def _service_status_running(self) -> bool:
        result = subprocess.run(
            ["service", "mariadb", "status"], capture_output=True, text=True, timeout=15.0,
        )
        return result.returncode == 0

    def _wait_for_ping(self) -> None:
        deadline = time.monotonic() + MARIADB_BOOT_TIMEOUT_S
        last: subprocess.CompletedProcess | None = None
        while time.monotonic() < deadline:
            last = subprocess.run(["mariadb-admin", "ping"], capture_output=True, text=True, timeout=5.0)
            if last.returncode == 0:
                return
            time.sleep(0.25)
        raise LiveBootError(
            f"mariadbd did not answer 'mariadb-admin ping' within {MARIADB_BOOT_TIMEOUT_S}s: "
            f"{last.stdout if last else ''}{last.stderr if last else ''}"
        )

    def start(self) -> None:
        """Start the real system `mariadbd` if it is not already running
        (never restarting/reconfiguring one that is), then wait for it to
        answer pings for real -- never assumed ready the instant `service
        start` returns."""
        self._we_started_service = not self._service_status_running()
        if self._we_started_service:
            result = subprocess.run(
                ["service", "mariadb", "start"], capture_output=True, text=True, timeout=60.0,
            )
            if result.returncode != 0:
                raise LiveBootError(
                    f"'service mariadb start' failed (exit {result.returncode}):\n"
                    f"{result.stdout}\n{result.stderr}"
                )
        self._wait_for_ping()

    def provision(self) -> None:
        """Drop any stale same-named database/user from a prior run, import
        the REAL `lab/sql/schema.sql` verbatim (`mariadb <
        schema.sql` -- it creates and seeds the database itself, so no
        separate `CREATE DATABASE` step is needed here), and create the
        least-privilege application user `lab/compose.yaml` itself connects
        as (never root, matching that file's own `PFF_DB_HOST`/`PFF_DB_USER`
        seam)."""
        self._root_run(
            f"DROP DATABASE IF EXISTS `{self.db_name}`; "
            f"DROP USER IF EXISTS '{self.db_user}'@'{self.host}';"
        )
        schema_sql = REAL_SCHEMA_SQL.read_text("utf-8")
        import_result = subprocess.run(
            ["mariadb", "-u", "root"], input=schema_sql, capture_output=True, text=True, timeout=60.0,
        )
        if import_result.returncode != 0:
            raise LiveBootError(
                f"importing {REAL_SCHEMA_SQL} into a real MariaDB failed (exit "
                f"{import_result.returncode}):\n{import_result.stdout}\n{import_result.stderr}"
            )
        user_result = self._root_run(
            f"CREATE USER '{self.db_user}'@'{self.host}' IDENTIFIED BY '{self.db_password}'; "
            f"GRANT ALL PRIVILEGES ON `{self.db_name}`.* TO '{self.db_user}'@'{self.host}'; "
            "FLUSH PRIVILEGES;"
        )
        if user_result.returncode != 0:
            raise LiveBootError(
                f"provisioning the '{self.db_user}' MariaDB user failed (exit "
                f"{user_result.returncode}):\n{user_result.stdout}\n{user_result.stderr}"
            )
        self._provisioned = True

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        """Read-only introspection over the real MariaDB database, mirroring
        :meth:`LiveBootHarness.query_db`'s role for the SQLite path -- for a
        test to observe a write a real HTTP request made, without a second,
        parallel HTTP-response-parsing mechanism.

        Deliberately shells out to the real `mariadb` client in batch mode
        (`-B`, tab-separated with a header row) rather than adding a Python
        MySQL driver dependency this project does not otherwise need
        (PA-0005: no runtime dependency the project has not declared) -- the
        harness's PHP side already talks to MariaDB through Laravel's own
        `pdo_mysql` driver, so a *second*, Python-side one would exist only
        for this introspection helper. `%s`-style placeholders in `sql` are
        substituted with `params` as quoted literals before the query is
        sent -- a plain, test-harness-only substitution (never used to
        compose an HTTP request this harness sends, only this read-only
        assertion helper), good enough for the fixed, hand-written queries
        this module's own tests pass it."""
        for value in params:
            literal = "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'" if isinstance(value, str) else str(value)
            sql = sql.replace("%s", literal, 1)
        result = subprocess.run(
            ["mariadb", "-h", self.host, "-P", str(self.port), "-u", self.db_user,
             f"-p{self.db_password}", self.db_name, "-B", "-e", sql],
            capture_output=True, text=True, timeout=30.0,
        )
        if result.returncode != 0:
            raise LiveBootError(f"query against real MariaDB failed (exit {result.returncode}): {result.stderr}")
        lines = result.stdout.splitlines()
        if not lines:
            return []
        header = lines[0].split("\t")
        return [dict(zip(header, line.split("\t"))) for line in lines[1:]]

    def teardown(self) -> None:
        """Drop the test database/user unconditionally, then stop `mariadbd`
        again -- but only if :meth:`start` is the one that started it (see
        the class docstring). Runs both steps even if one fails, and never
        raises: teardown must not itself become the reason a test run leaks
        state (PA-0012's bounded-teardown convention)."""
        if self._provisioned:
            self._root_run(
                f"DROP DATABASE IF EXISTS `{self.db_name}`; "
                f"DROP USER IF EXISTS '{self.db_user}'@'{self.host}';"
            )
        if self._we_started_service:
            subprocess.run(["service", "mariadb", "stop"], capture_output=True, text=True, timeout=30.0)

    def __enter__(self) -> "MariaDbServer":
        self.start()
        self.provision()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.teardown()


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
#: ``users``) -- **not** a port of ``lab/sql/schema.sql``
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
    """Run a real subprocess step of the live-boot pipeline (``composer
    install``, ``artisan key:generate``, ...) with an enforced, bounded
    ``timeout`` on every call site -- never left to the caller to remember
    (``BUG-0033``/PA-0035: a passing capability probe is not a substitute
    for every *later* real network/subprocess operation also being bounded
    on its own). A hung network mid-install now raises a clear, immediate
    :class:`LiveBootError` naming which step and after how long -- never an
    uncaught :class:`subprocess.TimeoutExpired` and never an indefinite
    hang."""
    try:
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiveBootError(
            f"{cmd[0]} did not complete within {timeout}s (cmd={cmd!r}): "
            f"stdout={exc.stdout!r} stderr={exc.stderr!r}"
        ) from exc


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str
    #: Response headers (CC-LAB-0210: the first caller of this harness that
    #: needs to observe a header rather than only status/body -- a real
    #: `Location:` header proof for the open-redirect shape). Additive: a
    #: default of `{}` keeps every pre-existing construction of this
    #: dataclass unchanged.
    headers: dict[str, str] = field(default_factory=dict)


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

    def __init__(
        self,
        emitter: Emitter,
        cells: list[Cell],
        *,
        install_timeout: float = 240.0,
        mariadb_server: "MariaDbServer | None" = None,
    ) -> None:
        """``mariadb_server`` (``CC-LAB-0058``/``FR-LAB-55``): when given an
        already-started, already-provisioned :class:`MariaDbServer`, this
        harness points the assembled app's `.env` at it (`DB_CONNECTION=mysql`)
        instead of the default per-run SQLite database, and skips seeding
        (that server's REAL `lab/sql/schema.sql` import already
        seeded real rows -- see :class:`MariaDbServer`'s own docstring for why
        this harness does not re-seed on top of it). ``None`` (the default)
        keeps this class's original SQLite behavior byte-for-byte -- this
        parameter is additive, never a change to an existing caller's
        behavior."""
        self._emitter = emitter
        self._cells = [c for c in cells if emitter.supports(c.vuln_class, c.sink_context)]
        self._install_timeout = install_timeout
        self._mariadb_server = mariadb_server
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
        if self._mariadb_server is not None:
            db = self._mariadb_server
            lines = (
                "APP_NAME=FuzzlabPhpLaravelLiveBootHarness",
                "APP_ENV=testing",
                "APP_KEY=",
                "APP_DEBUG=false",
                "APP_URL=http://127.0.0.1",
                "",
                "LOG_CHANNEL=stack",
                "LOG_LEVEL=error",
                "",
                "DB_CONNECTION=mysql",
                f"DB_HOST={db.host}",
                f"DB_PORT={db.port}",
                f"DB_DATABASE={db.db_name}",
                f"DB_USERNAME={db.db_user}",
                f"DB_PASSWORD={db.db_password}",
                "",
                "SESSION_DRIVER=file",
                "CACHE_STORE=file",
                "",
            )
            (self._app_dir / ".env").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
            return
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
        if self._mariadb_server is not None:
            # Real lab/sql/schema.sql already seeded real rows
            # (MariaDbServer.provision()) -- nothing to add here, see that
            # class's own docstring for why a second, synthetic seed step
            # would be exactly the PA-0003/PA-0021 drift this mode exists to
            # avoid.
            return
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
            return HttpResponse(
                status=resp.status,
                body=resp.read().decode("utf-8", errors="replace"),
                headers=dict(resp.headers.items()),
            )

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
