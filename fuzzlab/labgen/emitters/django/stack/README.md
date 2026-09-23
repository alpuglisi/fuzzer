# `django` `StackEnv` dependency pins and skeleton provenance

Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9 (category 2 pilot)
and `CC-LAB-0090` (Phase A).

## Version pin

`django==5.2.17`, resolved for real against a live PyPI index this session
(`python3 -m pip index versions django`, 2026-09-22) — the current stable
release at resolution time, matching `stack_env.py`'s
`DJANGO_STACK_ENV.framework_version`. No `requirements.txt`/lockfile lives
in this directory: unlike `php_laravel`'s Composer-based dependency
resolution (a `composer.lock` pinning 74 packages), this lane's real boot
(`fuzzlab.labgen.conformance.django_live_boot.DjangoLiveBootHarness`) is
**venv-based**, installing exactly one real package
(`pip install django==5.2.17`) into a scratch `venv` per run — no lockfile
is needed for a single-package, exact-pinned install.

## `base_image`

`python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0`
— resolved for real via a direct registry-API round trip (not
`docker manifest inspect`/`buildx imagetools`, both of which hit Docker
Hub's unauthenticated pull-rate limit in this sandbox at resolution time):
an anonymous bearer token + manifest-list fetch against
`public.ecr.aws/v2/docker/library/python/manifests/3.13-slim` — AWS's public
ECR gallery mirror of the same official Docker Hub `python` image, a
legitimate alternate registry for the identical upstream image, not a
different or unofficial one. The manifest-list (OCI image index) response's
own bytes hash to this digest (`sha256sum` of the raw response body — the
standard way an OCI index's own content-addressed digest is computed).
**Not consumed by this lane's actual boot mechanism** (see below) —
forward-looking metadata for a possible future container-based path, the
same role it already plays for `php_laravel`'s own `StackEnv.base_image`.

## `skeleton/` (`CC-LAB-0090`, 2026-09-22)

The real, minimal, **bootable** Django 5.2 project skeleton the live-boot
conformance harness (`fuzzlab.labgen.conformance.django_live_boot.
DjangoLiveBootHarness`) overlays a manifest's generated content onto.

**Provenance.** A real, un-doctored `django-admin startproject
fuzlab_django_lab .` run in a scratch `venv` (`django==5.2.17`, the same
version pinned above), 2026-09-22. Only the files this skeleton actually
needs at boot time are carried in as-is: `manage.py`,
`fuzlab_django_lab/__init__.py`, `fuzlab_django_lab/wsgi.py`. Everything
else the real generator output produces is deliberately **not** carried,
named here rather than silently dropped:

- `fuzlab_django_lab/settings.py` — **not** checked in as a static file.
  Rendered fresh at build time by `stack_env.settings_py_content()`
  (mirrors `php_laravel`'s own `.env`/`StackEnv.env_file_content()`
  convention — a scaffold file the harness writes per run, not a file on
  disk) so the safety-critical `DEBUG = False`/`ALLOWED_HOSTS` departure
  from the generator's own defaults (see that function's docstring for the
  full reasoning) is generated code, not something that could silently
  drift if the checked-in skeleton were ever regenerated from a newer
  Django release without re-applying the same edit by hand.
- `fuzlab_django_lab/urls.py` — **not** checked in. This is the
  `route`-category accumulator target (`CR-LAB-0001` Addendum D), built
  purely by `DjangoEmitter.render_route_accumulator()` from a manifest's
  supported cells — mirrors `node_express`'s own `app.js`, likewise absent
  from that stack's checked-in `scaffold/`.
- `fuzlab_django_lab/asgi.py` — dropped. This lane boots via `manage.py
  runserver` (WSGI dev server), never ASGI; no rendered cell needs async
  request handling.
- No Django "app" (`INSTALLED_APPS` entry, `AppConfig`, `migrations/`) is
  checked in. Phase A's one illustrative shape (`sqli`/
  `sql_numeric_literal`) uses a raw `connection.cursor()` sink on **both**
  twins — never the ORM — so it needs no model or its own migration; views
  live directly in the project package
  (`fuzlab_django_lab/views/`, one module per cell, generated). A
  documented divergence from `CC-LAB-0090`'s original draft (which sketched
  a generic `<app>/urls.py` accumulator target before this simplification
  was found during implementation) — reflected back into that entry per
  the pre-change review gate's own rule that "a real divergence found
  during implementation gets reflected back into the entry before the
  change is considered done." A later Phase B shape that needs the ORM
  (e.g. the mass-assignment-via-`ModelForm` class identified in
  `docs/research/category2-social-ugc-functionality-and-cwe-research.md`
  §4) will need a real Django app + migration at that point — not attempted
  here.

**No edits from the `django-admin startproject` output** for the three
files that are carried in (`manage.py`, `__init__.py`, `wsgi.py`) — each is
byte-for-byte what the generator produced, only the project name
(`fuzlab_django_lab`) chosen at generation time.

**Django/ORM defaults this harness's real `manage.py migrate` exercises**
(enumerated up front per `CC-LAB-0090`'s pre-change review, reviewer #2,
citing `PA-0030`/`BUG-0028`'s "enumerate framework/ORM defaults before
extending this harness family" rule):

- `django.contrib.auth`/`sessions`/`contenttypes` are kept in
  `INSTALLED_APPS` (`django.contrib.admin`/`messages`/`staticfiles` and
  `MessageMiddleware` are trimmed — dev-only/unused-by-this-lab tooling, the
  same "trim unused defaults" convention `php_laravel`'s own skeleton
  README documents). A real `migrate` therefore creates `auth_user`,
  `django_session`, `django_content_type`, and related tables even though
  Phase A's one shape touches none of them directly — recorded here so a
  later Phase B cell that does touch auth/sessions is not surprised by an
  undocumented default.
- `CsrfViewMiddleware` is on by default and will reject an unsafe
  (`POST`/etc.) request with no valid CSRF token. Phase A's one shape is
  `GET`-only, so this does not block anything here — recorded so Phase B's
  first `POST`-shaped cell doesn't hit it as a surprise; the real
  `puppy-fort-factory`-derived pages this project's other stacks reproduce
  have no CSRF framework of their own (`php_laravel`'s own skeleton README
  documents disabling Laravel's default CSRF middleware for exactly this
  reason), so the likely resolution when that cell is built is the same:
  either `@csrf_exempt` the generated view or disable the middleware for
  this lab, decided when that cell actually exists, not here.
- Django models default to an auto-incrementing integer `id` primary key
  unless a model overrides it — not exercised by Phase A (no model exists
  yet), recorded so a later cell needing a non-default PK shape doesn't
  silently inherit an unstated assumption.

## SBOM

`syft` was **not available** on this build host (`which syft` — not
found), mirroring `php_laravel`'s own documented gap. Per that same
fallback convention, a `pip list --format=freeze` capture of the scratch
`venv` used to resolve the version pin above is recorded instead:

```
Django==5.2.17
asgiref==3.12.1
sqlparse==0.6.0
```

(the real, observed output of `pip list --format=freeze` in the scratch
`venv` this session actually built and ran `django-admin startproject` in
— not estimated. Django's own only two runtime dependencies, `asgiref` and
`sqlparse`, both resolved at their own latest-compatible versions at
resolution time, 2026-09-22; `pip`/`setuptools` themselves omitted as
build tooling, not application dependencies). The intended `syft` command, once available:

```sh
syft dir:fuzzlab/labgen/emitters/django/stack -o cyclonedx-json \
    > fuzzlab/labgen/emitters/django/stack/sbom.cdx.json
```

## Scope

This skeleton is a test-harness / conformance-check asset, exactly like
`php_laravel/stack/skeleton/`'s own scope note — not wired into the real
lab's Docker-based deployment (`lab/compose.yaml`, `deploy.sh`).
