"""Live-boot conformance check for `django` Phase A (category 2 pilot,
`CC-LAB-0090`).

Unlike most `tests/test_labgen_*` modules, this one is a **real, on-host
integration test** -- mirrors `test_labgen_conformance_live_boot.py`'s own
scope statement, adapted to the `django` stack: it assembles a real Django
5.2 project from the checked-in skeleton plus a real manifest-shaped
`DjangoEmitter` output, runs a real `pip install django==<pinned>` against
PyPI (in a scratch `venv`), migrates + seeds a real per-run SQLite database,
boots a real `manage.py runserver` process (forced to `127.0.0.1`), and
makes real HTTP requests against it -- entirely within this test run, its
own temp directory/venv/port/process torn down on every exit path (context
manager), never left running or leaked.

Skip-guarded (PA-0005) on `django_boot_available()` -- python3/venv present
and PyPI actually reachable through a real, bounded `pip download` round
trip -- so this SKIPS cleanly, not fails, in any environment without them.
Marked `@pytest.mark.slow` (a real `pip install` + `venv` creation against
the network, tens of seconds).

**What this proves, and what it does not:** see
`fuzzlab/labgen/conformance/django_live_boot.py`'s own module docstring for
the full scope statement. In short: real boot + real HTTP responses + a
real payload differential on Phase A's one illustrative
`sqli`/`sql_numeric_literal` vulnerable/secure twin, against a per-run
SQLite database -- and, load-bearing per `CC-LAB-0090`'s pre-change review
(reviewer #2), that the vulnerable twin's real error-path response is
Django's *plain* 500 page (`DEBUG = False` actually enforced, not merely
asserted in `settings.py`'s source) -- never a live-lab-grade
dialect-sensitive oracle confirmation, and never the full module-inventory
depth (a separate, later Phase B).
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness, django_boot_available
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not django_boot_available(),
        reason=(
            "django live-boot harness requires python3/venv on PATH and real PyPI "
            "network reachability (PA-0005) -- see django_live_boot.django_boot_available()"
        ),
    ),
]

_ROUTE = Route(method="GET", path="/api/products")
_SINK_CONTEXT = SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",))

#: A single-quote payload that breaks unparameterized SQL syntax on the
#: vulnerable twin but is safely treated as a non-matching literal string by
#: the secure twin's parameterized `%s` placeholder -- the same
#: syntax-break-vs-safely-bound differential every other stack's first
#: live-boot test proves (`php_laravel`'s `product.php`, `node_express`'s
#: `/api/products`).
_SQLI_PAYLOAD = "1' OR '1'='1"


def _vuln_cell() -> Cell:
    return Cell(
        cell_id="LABGEN-DJ-0001",
        vuln_class="sqli",
        stack_profile="django",
        route=_ROUTE,
        sink_context=_SINK_CONTEXT,
        transform=Pipeline(ops=()),
    )


def _secure_cell() -> Cell:
    return Cell(
        cell_id="LABGEN-DJ-0002",
        vuln_class="sqli",
        stack_profile="django",
        route=_ROUTE,
        sink_context=_SINK_CONTEXT,
        transform=Pipeline(ops=("param_bind",)),
    )


def test_django_live_boot_normal_lookup_both_twins() -> None:
    """A real, legitimate `id=1` request returns the real seeded row on
    both the vulnerable and secure twin -- proves the shared happy path
    (source -> sink -> response) works identically before the two twins'
    behavior is compared on the adversarial payload below."""
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, [_vuln_cell(), _secure_cell()]) as harness:
        vuln_resp = harness.get("/generated/labgen_dj_0001/", params={"id": "1"})
        secure_resp = harness.get("/generated/labgen_dj_0002/", params={"id": "1"})

    assert vuln_resp.status == 200
    assert '"name": "Chew Toy"' in vuln_resp.body
    assert secure_resp.status == 200
    assert '"name": "Chew Toy"' in secure_resp.body


def test_django_live_boot_sqli_payload_differential() -> None:
    """The real payload differential this Phase A lane exists to prove:
    the vulnerable twin's unparameterized string-concatenated query breaks
    on the adversarial payload (a real 500 -- SQLite reports the malformed
    SQL as an error), while the secure twin's parameterized `%s` placeholder
    treats the exact same payload as a literal, non-matching string value
    (a real 404 -- no row matches, not a syntax error)."""
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, [_vuln_cell(), _secure_cell()]) as harness:
        vuln_resp = harness.get("/generated/labgen_dj_0001/", params={"id": _SQLI_PAYLOAD})
        secure_resp = harness.get("/generated/labgen_dj_0002/", params={"id": _SQLI_PAYLOAD})

    assert vuln_resp.status == 500
    assert secure_resp.status == 404


def test_django_live_boot_debug_false_no_traceback_leak() -> None:
    """`CC-LAB-0090`'s pre-change review (reviewer #2) made this the load-
    bearing safety check for this lane: Django's own default debug page
    (`DEBUG = True`) renders a full traceback, local-variable dump, and
    `SECRET_KEY`-adjacent settings on exactly the unhandled-exception path
    the vulnerable twin's SQLi payload triggers -- contaminating this
    cell's single labeled vulnerability class with an unlabeled
    full-disclosure secondary one. This test verifies the *real* HTTP
    response body, not merely that `settings.py`'s source text contains
    `DEBUG = False` -- a real generated `.py` file could still diverge from
    what actually got served."""
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, [_vuln_cell()]) as harness:
        resp = harness.get("/generated/labgen_dj_0001/", params={"id": _SQLI_PAYLOAD})

    assert resp.status == 500
    lowered = resp.body.lower()
    # Django's real debug page (DEBUG=True) includes these literal strings;
    # its plain 500 page (DEBUG=False) does not. Checking their absence is a
    # real assertion about the served bytes, not an inference from settings.
    assert "traceback" not in lowered
    assert "secret_key" not in lowered
    assert "django version" not in lowered
