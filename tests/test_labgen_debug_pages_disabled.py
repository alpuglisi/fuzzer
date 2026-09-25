"""PA-0057 (from BUG-0055, CC-LAB-0245): every stack's *served* build -- the
real deployment path **and** every test-time live-boot launch -- runs with its
framework's debug / exception-detail pages disabled. Mechanical and
cross-emitter by design: the requirement already existed as prose
(``docs/LAB_IMPLEMENTATION_PLAN.md``'s "production-equivalent mode by default
as a blanket rule") and as per-stack docstrings, and the ``ruby_rails`` port
still shipped with Rails' detailed exception pages on -- an anonymous request
could read the generated controller source, transform comment included, and
so tell the vulnerable twin from the secure one (BUG-0055).

One check per stack, each reading the setting that actually governs its
debug output, at the place the running app actually takes it from:

* ``ruby_rails``: the skeleton environment file the live-boot harness boots
  (``RAILS_ENV`` from the harness itself) -- ``consider_all_requests_local`` and
  ``annotate_rendered_view_with_filenames`` both ``false``.
* ``php_laravel``: ``APP_DEBUG=false`` in both the deployment ``.env``
  (``StackEnv.env_file_content``) and the live-boot harness's own ``.env``.
* ``django``: the generated ``settings.py`` has ``DEBUG = False``.
* ``python_fastapi``: no ``debug=True``; the schema/docs routes disabled.
* ``node_express``: ``NODE_ENV=production`` in the deployment Dockerfile, and
  -- currently NOT met, pinned by a strict xfail below (PA-0054(3)) -- in
  every test-time ``node app.js`` launch.
* ``spring_boot``: no devtools/actuator dependency, no stack traces in error
  responses.
* ``go_net_http``: no ``net/http/pprof`` debug handlers.

``php_current`` is not served by any harness or deployment (Phase 0, offline
rendering only), so it has no debug posture to check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EMITTERS = REPO / "fuzzlab" / "labgen" / "emitters"


def _code_lines(text: str, comment: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith(comment))


def test_ruby_rails_booted_environment_has_debug_pages_off() -> None:
    from fuzzlab.labgen.conformance.rails_live_boot import SKELETON_DIR, RailsLiveBootHarness
    from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter

    env = RailsLiveBootHarness(RailsEmitter(), [])._harness_env()["RAILS_ENV"]
    code = _code_lines((SKELETON_DIR / "config" / "environments" / f"{env}.rb").read_text(encoding="utf-8"), "#")
    assert re.findall(r"config\.consider_all_requests_local\s*=\s*(\w+)", code) == ["false"]
    assert re.findall(r"config\.action_view\.annotate_rendered_view_with_filenames\s*=\s*(\w+)", code) == ["false"]


def test_php_laravel_deployment_and_harness_env_have_app_debug_false() -> None:
    from fuzzlab.labgen.conformance.live_boot import _harness_env_content
    from fuzzlab.labgen.emitters.php_laravel.stack_env import PHP_LARAVEL_STACK_ENV

    for content in (PHP_LARAVEL_STACK_ENV.env_file_content(), _harness_env_content(app_key="base64:x")):
        lines = content.decode("utf-8").splitlines()
        assert "APP_DEBUG=false" in lines
        assert "APP_DEBUG=true" not in lines


def test_django_settings_have_debug_false() -> None:
    from fuzzlab.labgen.emitters.django.stack_env import settings_py_content

    code = _code_lines(settings_py_content().decode("utf-8"), "#")
    assert re.findall(r"^DEBUG\s*=\s*(\w+)", code, re.M) == ["False"]


def test_python_fastapi_has_no_debug_and_no_schema_routes() -> None:
    text = (EMITTERS / "python_fastapi" / "templates" / "scaffold" / "main.py.j2").read_text(encoding="utf-8")
    for setting in ("docs_url=None", "redoc_url=None", "openapi_url=None"):
        assert setting in text
    assert "debug=True" not in text


def test_node_express_deployment_image_sets_production() -> None:
    dockerfile = (EMITTERS / "node_express" / "scaffold" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^ENV NODE_ENV=production$", dockerfile, re.M)


def _node_app_launch_files() -> list[Path]:
    return sorted(p for p in (REPO / "tests").glob("*.py") if '"node", "app.js"' in p.read_text(encoding="utf-8"))


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG-0055 PA-0002 sweep, flagged to the Browsable Labs orchestrator (node_express is "
        "Lane 6's emitter, not fixed in CC-LAB-0245): the test-time `node app.js` launches in "
        "tests/test_labgen_node_bff_app.py, tests/test_labgen_node_bff_multitarget.py and "
        "tests/test_multitarget_category1_combined.py pass env={**os.environ, 'PORT': ...} without "
        "NODE_ENV=production, so Express's default error handler would write err.stack into "
        "error responses (found by reading, not live-verified here). Fixing every launch site "
        "turns this into an XPASS -- remove the xfail then."
    ),
)
def test_every_test_time_node_launch_sets_production() -> None:
    files = _node_app_launch_files()
    assert files, "no node app.js launch sites found -- the check would pass vacuously"
    missing = [p.name for p in files if '"NODE_ENV": "production"' not in p.read_text(encoding="utf-8")]
    assert missing == []


def test_node_launch_sweep_is_not_vacuous() -> None:
    # The strict xfail above must be failing for the documented reason, not
    # because it found nothing to check.
    assert len(_node_app_launch_files()) >= 3


def test_spring_boot_has_no_devtools_actuator_or_stacktraces() -> None:
    skeleton = EMITTERS / "spring_boot" / "stack" / "skeleton"
    pom = (skeleton / "pom.xml").read_text(encoding="utf-8")
    assert "spring-boot-devtools" not in pom
    assert "spring-boot-starter-actuator" not in pom
    props = _code_lines((skeleton / "src" / "main" / "resources" / "application.properties").read_text(encoding="utf-8"), "#")
    assert "include-stacktrace=always" not in props
    assert "include-exception=true" not in props


def test_go_net_http_serves_no_pprof_debug_handlers() -> None:
    hits = [p for p in (EMITTERS / "go_net_http").rglob("*") if p.is_file() and p.suffix in (".go", ".j2", ".py")
            and "net/http/pprof" in p.read_text(encoding="utf-8", errors="replace")]
    assert hits == []
