"""``StackEnv`` for the ``django`` stack (category 2 pilot, `CC-LAB-0090`).

Reuses :class:`fuzzlab.labgen.emitters.php_laravel.stack_env.StackEnv` --
confirmed (`CC-LAB-0090`'s pre-change review, reviewer #1) to be genuinely
stack-agnostic *data* (no Laravel-specific fields on the dataclass itself).
This module does **not** import or call that sibling module's
``env_file_content()``/``index_php_content()`` methods -- those are two
methods defined on that same class that ARE hard-coded PHP/Laravel content
(``.env`` keys, a literal ``<?php`` front controller); Django's own
``settings.py``/``manage.py`` content is rendered from scratch below,
never routed through them.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.php_laravel.stack_env import StackEnv

__all__ = ["DJANGO_STACK_ENV", "StackEnv", "settings_py_content"]


#: The single ``django`` ``StackEnv``. ``framework_version`` resolved for
#: real against a live PyPI index this session (``pip index versions
#: django`` -- see `CC-LAB-0090`'s pre-change review, reviewer #1,
#: independently confirmed). ``base_image`` resolved for real via a direct
#: registry-API round trip against AWS's public ECR mirror of the official
#: Docker Hub ``python`` image (``public.ecr.aws/docker/library/python`` --
#: Docker Hub's own unauthenticated pull quota was exhausted in this
#: sandbox at resolution time, so the request went to a legitimate
#: alternate mirror of the same official image rather than a fabricated
#: value): manifest-list (OCI image index) digest for the ``3.13-slim`` tag,
#: 2026-09-22. This lane's real boot is **venv-based, not container-based**
#: (mirroring ``node_express``'s own Phase A scope -- no Docker daemon
#: needed for a local boot-and-serve harness), so ``base_image`` is
#: forward-looking metadata for a possible future container path, not
#: consumed by :mod:`fuzzlab.labgen.conformance.django_live_boot`'s actual
#: boot mechanism -- the same role it already plays for `php_laravel`,
#: whose own ``LiveBootHarness`` also boots locally via ``php artisan
#: serve``, never the container.
DJANGO_STACK_ENV = StackEnv(
    language="python",
    framework="django",
    framework_version="5.2.17",
    base_image=(
        "python:3.13-slim@"
        "sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0"
    ),
    workdir="/srv/app",
    # Nominal command shape only -- `DjangoLiveBootHarness.build()` forces
    # `127.0.0.1` (never this field's literal `0.0.0.0`) when it actually
    # boots the process, per CLAUDE.md's non-negotiable Safety section
    # (loopback-only, never exposed) and matching the *actual* precedent
    # this stack is modeled on: `php_laravel`'s own `StackEnv.entrypoint_cmd`
    # also nominally says `--host=0.0.0.0`, but the real `LiveBootHarness`
    # code silently overrides it to `127.0.0.1` at `live_boot.py`'s
    # `build()` -- stated explicitly here rather than left to silent
    # analogy, per `CC-LAB-0090`'s pre-change review (reviewer #2).
    entrypoint_cmd=("python", "manage.py", "runserver", "0.0.0.0:8000"),
    is_multi_file=True,
    # No separate Django "app" (`INSTALLED_APPS` entry/`AppConfig`) is
    # needed for Phase A's one illustrative shape -- it uses a raw
    # `cursor.execute()` sink on both twins (never the ORM), so it needs no
    # model/migration of its own. Views live directly in the project
    # package (`fuzlab_django_lab/views/`), a documented simplification
    # from `CC-LAB-0090`'s original draft (which sketched a generic
    # `<app>/urls.py` accumulator target) -- reflected back into that entry
    # per the pre-change review gate's own "a real divergence found during
    # implementation gets reflected back into the entry" rule. `manage.py`
    # and `fuzlab_django_lab/wsgi.py` are rendered once (real, unmodified
    # `django-admin startproject` output); `fuzlab_django_lab/settings.py`
    # is rendered once with `DEBUG`/`ALLOWED_HOSTS` forced (see
    # `settings_py_content` below) -- both are real project-level files, not
    # per-cell.
    scaffold_files=("manage.py", "fuzlab_django_lab/wsgi.py", "fuzlab_django_lab/settings.py"),
    # `fuzlab_django_lab/urls.py` is the one accumulator file (the
    # `route`-category, cardinality `accumulator` per `CR-LAB-0001`
    # Addendum D): one route-registration line per supported cell, sorted
    # by cell ID at render time -- never checked into the skeleton (mirrors
    # `node_express`'s own `app.js`, which is likewise absent from that
    # stack's checked-in `scaffold/` and built purely by
    # `NodeExpressEmitter.render_route_accumulator`).
    accumulators=("fuzlab_django_lab/urls.py",),
    file_roles={
        # One view-function module per cell (this emitter's controller
        # analogue) -- mirrors `php_laravel`'s per-cell `controller` role,
        # adapted to Django's plain-function-view idiom (no class needed
        # for this shape).
        "view": "fuzlab_django_lab/views/{cell_slug}.py",
        "route": "fuzlab_django_lab/urls.py",
    },
)


def settings_py_content(*, secret_key: str = "django-insecure-FAKE-lab-only-placeholder-not-a-real-secret") -> bytes:
    """Render the scaffold's ``fuzlab_django_lab/settings.py``.

    Real, trimmed ``django-admin startproject`` output (Django 5.2.17,
    resolved 2026-09-22) with three deliberate departures from the
    generator's own defaults, all safety/correctness requirements per
    `CC-LAB-0090`'s pre-change review (reviewer #2), not optional
    follow-ups:

    - **``DEBUG = False``** (the generator's own default is ``True``).
      Left on, Django's own detailed debug page renders a full traceback,
      local-variable dump, and ``SECRET_KEY``-adjacent settings on any
      unhandled exception -- and the one illustrative shape this lane
      builds (a raw ``cursor.execute()`` SQLi cell) will readily trigger
      exactly that exception path on a malformed payload. Left on, every
      generated page's single labeled vulnerability class would be
      contaminated with an unlabeled full-disclosure secondary one --
      the same reasoning that already forced `php_laravel`'s
      ``APP_DEBUG=false`` (see that stack's own ``stack_env.py``
      docstring, citing D20) and FastAPI's disabled ``/docs``.
    - **A real, non-wildcard ``ALLOWED_HOSTS``** (the generator's own
      default is ``[]``, which Django would otherwise reject every request
      against with a 400 once ``DEBUG = False`` -- so this is not
      optional once the line above is applied, it is required for the app
      to serve any request at all).
    - **Trimmed ``INSTALLED_APPS``/``MIDDLEWARE``**: ``django.contrib.
      admin``, ``django.contrib.messages``, and ``django.contrib.
      staticfiles`` (and ``MessageMiddleware``) are dropped -- dev-only/
      unused-by-this-lab tooling, per the same "trim unused defaults"
      convention `php_laravel/stack/skeleton/README.md` documents for its
      own composer scaffold. ``django.contrib.auth``/``sessions``/
      ``contenttypes`` are kept (a real ``manage.py migrate`` still
      creates their tables -- ``auth_user``, ``django_session``,
      ``django_content_type`` -- enumerated explicitly here per
      `CC-LAB-0090`'s `PA-0030`/`BUG-0028` finding, so a later Phase B
      cell that touches auth/sessions is not surprised by an
      undocumented default).
    """
    content = (
        '"""\n'
        "Django settings for fuzlab_django_lab project (fuzzlab django emitter,\n"
        "CC-LAB-0090). Generated by 'django-admin startproject' using Django\n"
        f"5.2.17, then trimmed -- see this module's settings_py_content() docstring\n"
        "for the exact departures from the generator's own defaults and why each\n"
        "one is a correctness/safety requirement, not a follow-up.\n"
        '"""\n'
        "\n"
        "from pathlib import Path\n"
        "\n"
        "BASE_DIR = Path(__file__).resolve().parent.parent\n"
        "\n"
        f'SECRET_KEY = "{secret_key}"\n'
        "\n"
        "# Correctness requirement, not a follow-up -- see settings_py_content()'s\n"
        "# own docstring: DEBUG left on would leak a full traceback + \n"
        "# SECRET_KEY-adjacent settings on any unhandled exception, contaminating\n"
        "# every generated page's single labeled vulnerability class with an\n"
        "# unlabeled full-disclosure secondary one.\n"
        "DEBUG = False\n"
        'ALLOWED_HOSTS = ["127.0.0.1", "localhost"]\n'
        "\n"
        "INSTALLED_APPS = [\n"
        '    "django.contrib.auth",\n'
        '    "django.contrib.contenttypes",\n'
        '    "django.contrib.sessions",\n'
        "]\n"
        "\n"
        "MIDDLEWARE = [\n"
        '    "django.middleware.security.SecurityMiddleware",\n'
        '    "django.contrib.sessions.middleware.SessionMiddleware",\n'
        '    "django.middleware.common.CommonMiddleware",\n'
        '    "django.middleware.csrf.CsrfViewMiddleware",\n'
        '    "django.contrib.auth.middleware.AuthenticationMiddleware",\n'
        '    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n'
        "]\n"
        "\n"
        'ROOT_URLCONF = "fuzlab_django_lab.urls"\n'
        "\n"
        "TEMPLATES = [\n"
        "    {\n"
        '        "BACKEND": "django.template.backends.django.DjangoTemplates",\n'
        # CC-LAB-0093: a real, project-level templates directory --
        # needed the first time a cell renders through Django's real
        # template engine (django.shortcuts.render()) rather than a
        # hand-built HttpResponse string. No Django "app" exists to
        # provide APP_DIRS-discovered templates, so this is the only
        # template search path.
        '        "DIRS": [BASE_DIR / "fuzlab_django_lab" / "templates"],\n'
        '        "APP_DIRS": True,\n'
        '        "OPTIONS": {\n'
        '            "context_processors": [\n'
        '                "django.template.context_processors.request",\n'
        '                "django.contrib.auth.context_processors.auth",\n'
        "            ],\n"
        "        },\n"
        "    },\n"
        "]\n"
        "\n"
        'WSGI_APPLICATION = "fuzlab_django_lab.wsgi.application"\n'
        "\n"
        "DATABASES = {\n"
        '    "default": {\n'
        '        "ENGINE": "django.db.backends.sqlite3",\n'
        '        "NAME": BASE_DIR / "db.sqlite3",\n'
        "    }\n"
        "}\n"
        "\n"
        'LANGUAGE_CODE = "en-us"\n'
        'TIME_ZONE = "UTC"\n'
        "USE_I18N = True\n"
        "USE_TZ = True\n"
        "\n"
        'DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"\n'
    )
    return content.encode("utf-8")
