"""``StackEnv`` for the ``php_laravel`` stack (lane L-P3.3a, §4.3 step 1).

Per ``CR-LAB-0001`` Addendum D, a routed, multi-file emitter needs more
per-stack metadata than :mod:`fuzzlab.labgen.emitter`'s ``Emitter``/
``EmittedFile`` pair alone carries -- the digest-pinned base image, the
files rendered once per build (``scaffold_files``), which output files are
fed one fragment per cell (``accumulators``), and the per-artifact-type path
templates (``file_roles``). :class:`StackEnv` is that per-stack record,
adapted from BaxBench's ``Env`` (see Addendum D point 3) -- it is data, not
behavior: :mod:`fuzzlab.labgen.emitters.php_laravel` (the ``Emitter``
implementation) reads it, nothing renders directly off it.

``php_current`` (Phase 0, filesystem-routed, no central routes file) has no
equivalent object -- ``EmittedFile.role`` defaults to ``"page"`` and that is
the whole story for that stack. Laravel is this project's first stack that
needs the extended schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StackEnv:
    """Per-stack build/runtime metadata for a routed, multi-file emitter.

    Every field is data (str/bool/tuple/dict of strings) so a ``StackEnv``
    instance is trivially hashable/comparable and safe to embed in a
    provenance comment or a snapshot test -- no callables, no mutable
    containers.
    """

    language: str
    framework: str
    framework_version: str
    #: Digest-pinned, e.g. ``"php:8.3-fpm-alpine@sha256:<64 hex chars>"``.
    #: Never a bare tag -- a tag is mutable and would silently drift the
    #: base image out from under a byte-identical-reproduction claim.
    base_image: str
    workdir: str
    entrypoint_cmd: tuple[str, ...]
    #: Whether this stack's emitter produces more than one file per build
    #: (always ``True`` for a routed framework -- controllers, views, a
    #: routes file, migrations -- as opposed to ``php_current``'s
    #: one-file-per-cell, filesystem-routed model).
    is_multi_file: bool
    #: Files rendered exactly once per build, never per cell (e.g. ``.env``,
    #: ``composer.json``, the front controller). Populated by
    #: :meth:`fuzzlab.labgen.emitters.php_laravel.LaravelEmitter.render_scaffold`,
    #: not by this dataclass itself -- ``scaffold_files`` here just *names*
    #: the paths so a caller can enumerate what a full build's scaffold
    #: consists of without importing the emitter.
    scaffold_files: tuple[str, ...] = field(default_factory=tuple)
    #: Output paths fed by exactly one fragment per cell, merged and sorted
    #: by cell ID at render time (Addendum D's accumulator rule) -- never by
    #: append/iteration order, since an unsorted accumulator would reshuffle
    #: on every new cell and break the byte-identical-source gate.
    accumulators: tuple[str, ...] = field(default_factory=tuple)
    #: Per-cell artifact type -> path template (``{cell_slug}`` is the only
    #: placeholder any current template uses; a future template may add
    #: more without changing this dataclass's shape).
    file_roles: dict[str, str] = field(default_factory=dict)

    def env_file_content(self) -> bytes:
        """Render the scaffold's ``.env`` file.

        **Debug mode is disabled** (``APP_DEBUG=false``, ``APP_ENV=production``)
        -- a correctness requirement for this task, not a follow-up: Laravel's
        Ignition debug page renders full stack traces plus every environment
        variable (DB/API credentials included) when ``APP_DEBUG=true``, which
        would hand an attacker of this *deliberately vulnerable* lab a second,
        unintended full-credential-disclosure vulnerability on every page,
        contaminating every cell's intended, single, labeled vulnerability
        class with an unlabeled one. See ``docs/DECISIONS_AND_ROADMAP.md`` D20
        and this lane's task brief; mirrors ``CR-LAB-0001``'s Phase 3 FastAPI
        lane disabling ``/docs`` for the same reason.
        """
        lines = (
            f"APP_NAME=FuzzlabPhpLaravelLab",
            "APP_ENV=production",
            "APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "APP_DEBUG=false",
            "APP_URL=http://127.0.0.1:8000",
            "",
            "LOG_CHANNEL=stack",
            "LOG_LEVEL=error",
            "",
            "DB_CONNECTION=mysql",
            "DB_HOST=127.0.0.1",
            "DB_PORT=3306",
            "DB_DATABASE=fuzzlab_lab",
            "DB_USERNAME=fuzzlab_lab",
            "DB_PASSWORD=FAKE-lab-only-placeholder",
            "",
            "SESSION_DRIVER=file",
            "CACHE_STORE=file",
            "",
        )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def index_php_content(self) -> bytes:
        """Render the scaffold's ``public/index.php`` front controller.

        A minimal, deterministic stand-in for Laravel's real generated front
        controller -- enough to prove ``StackEnv``/scaffold plumbing end to
        end for this foundation-only lane; the full bootstrap
        (``bootstrap/app.php`` service-provider wiring, etc.) is real-app
        migration work (§4.3 step 6, lane L-P3.3c), out of scope here.
        """
        content = (
            "<?php\n"
            "// Generated by fuzzlab.labgen.emitters.php_laravel (StackEnv scaffold).\n"
            "// APP_DEBUG is forced off in .env -- see StackEnv.env_file_content().\n"
            "\n"
            "define('LARAVEL_START', microtime(true));\n"
            "\n"
            "require __DIR__.'/../vendor/autoload.php';\n"
            "\n"
            "$app = require_once __DIR__.'/../bootstrap/app.php';\n"
            "\n"
            "$app->handleRequest(\\Illuminate\\Http\\Request::capture());\n"
        )
        return content.encode("utf-8")


#: The single ``php_laravel`` ``StackEnv`` (lane L-P3.3a). ``framework_version``
#: and ``base_image`` were resolved for real against Packagist/Docker Hub on
#: 2026-09-21, not guessed -- see this module's ``__init__.py`` sibling
#: docstring and ``docs/components/01-target-lab/change-control.md``
#: (CC-LAB-0029) for the resolution commands/evidence.
PHP_LARAVEL_STACK_ENV = StackEnv(
    language="php",
    framework="laravel",
    framework_version="13.32.0",
    base_image=(
        "php:8.3-fpm-alpine@"
        "sha256:62f4c401dc970c352223dd018e4f2c9d1c480e07f67351cd31bec2d1f8a8fb42"
    ),
    workdir="/var/www/html",
    entrypoint_cmd=("php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"),
    is_multi_file=True,
    scaffold_files=(".env", "public/index.php"),
    accumulators=("routes/web.php",),
    file_roles={
        "controller": "app/Http/Controllers/{cell_slug}Controller.php",
        # An HTML-sink cell is a two-file cell on this stack: a controller
        # plus its own Blade view (L-P3.3b's full-depth inventory). One view
        # per cell, named from the cell ID like every other per-cell artifact
        # here, so a minimal pair's twins never share a view file.
        "view": "resources/views/cells/{cell_slug}.blade.php",
        # The `json_view` view category's artifact (L-P3.3c-G2): an Eloquent
        # API Resource class, which is Laravel's view layer for a JSON
        # response. Keyed by the view module's own name, so a second view
        # category added later declares its own path template here rather than
        # overloading the Blade `view` entry.
        "json_view": "app/Http/Resources/{cell_slug}Resource.php",
        # A `stored_second_order` cell (L-P3.3c-G4) has two endpoints and so a
        # second controller: the *write* endpoint the payload is submitted to,
        # alongside the read/sink controller above. Additive -- a `direct`
        # cell never reaches this role, so every pre-existing cell's emitted
        # file set is unchanged.
        "write_controller": "app/Http/Controllers/{cell_slug}WriteController.php",
        "route": "routes/web.php",
    },
)
