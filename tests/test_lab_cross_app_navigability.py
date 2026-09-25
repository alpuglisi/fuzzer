"""CC-LAB-0247 (Lane 7, Gate F/F2): one combined pytest run proving all 10
browsable-app builds -- the exact 10 in `docs/LAB_BROWSABLE_APPS_PLAN.md`'s
port table (CircleFeed/HuddleHub/Booking, PicTrail, LoopCast, TrackerNest/
ReelQueue/WanderFare, ForgeCart, MeadowMart; the generic `python_fastapi`
sample has no app identity and is deliberately excluded, per that plan) --
can build and boot *in the same combined run*.

Per the plan's own R2 recommendation (§5, already decided, not open): this
does **not** need a real compose boot. It reuses each stack's own
in-process/subprocess live-boot harness -- the SAME fixture each stack's
own `test_labgen_<stack>_navigability_live_boot.py` module already defines
and already exercises far more thoroughly there (full per-URL ground-truth
status assertions) -- imported directly into this module *by name*
(a supported pytest pattern: a fixture is resolved by the attribute name
visible in the collecting module's namespace, wherever it was originally
defined), never re-derived (PA-0002/PA-0027: "derive, never hand-maintain a
second mechanism", applied here to test fixtures instead of production
code). This module's own job is narrower and genuinely new: nothing before
Lane 7 proved these 10 builds can all boot together without cross-
interference (shared ports, global module state, etc.) -- each stack's own
navigability module only ever boots its own app in isolation.

Each row is independently skip-guarded on that stack's own
`*_boot_available()` capability probe (or node/npm's own), so a host
missing e.g. `java`+`mvn` skips only that row, not the whole module
(mirrors every source navigability module's own `pytestmark` skip, applied
per-test here since a module-wide `pytestmark` would skip the whole file on
the first unavailable stack).

Run: `python3 -m pytest tests/test_lab_cross_app_navigability.py -v`
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.django_live_boot import django_boot_available
from fuzzlab.labgen.conformance.go_live_boot import go_boot_available
from fuzzlab.labgen.conformance.live_boot import live_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import spring_boot_boot_available
from fuzzlab.labgen.conformance.rails_live_boot import rails_boot_available

from .test_labgen_django_navigability_live_boot import _MIN_DISCOVERED_PAGES as _DJANGO_MIN_PAGES
from .test_labgen_django_navigability_live_boot import crawl as django_crawl
from .test_labgen_go_net_http_navigability_live_boot import _MIN_DISCOVERED_PAGES as _GO_MIN_PAGES
from .test_labgen_go_net_http_navigability_live_boot import crawl as go_crawl
from .test_labgen_navigability_live_boot import _SPECS as _PHP_SPECS
from .test_labgen_navigability_live_boot import crawls as php_crawls
from .test_labgen_node_meadowmart_navigability_live_boot import _MIN_CRAWLED_URLS as _NODE_MIN_PAGES
from .test_labgen_node_meadowmart_navigability_live_boot import app_root  # noqa: F401 -- node_crawl's own fixture dependency
from .test_labgen_node_meadowmart_navigability_live_boot import crawl as node_crawl
from .test_labgen_ruby_rails_navigability_live_boot import _MIN_DISCOVERED_PAGES as _RAILS_MIN_PAGES
from .test_labgen_ruby_rails_navigability_live_boot import site as rails_site
from .test_labgen_spring_boot_navigability_live_boot import _APPS as _SPRING_APPS
from .test_labgen_spring_boot_navigability_live_boot import crawl as spring_crawl

pytestmark = [pytest.mark.slow]

#: Populated as each row runs; the module-scoped `_summary` fixture (below,
#: autouse + session-ordering-independent since each test appends its own
#: row) prints this as the "per-app summary table" Gate F's own handoff
#: document asks for.
_ROWS: list[tuple[str, str, bool, str]] = []  # (stack, app, ok, detail)


def _record(stack: str, app: str, ok: bool, detail: str) -> None:
    _ROWS.append((stack, app, ok, detail))


@pytest.fixture(scope="session", autouse=True)
def _print_summary_at_session_end():
    yield
    if not _ROWS:
        return
    width = max(len(f"{stack}/{app}") for stack, app, _, _ in _ROWS)
    print("\n\n=== Lane 7 cross-app navigability: per-app summary ===")
    for stack, app, ok, detail in _ROWS:
        label = f"{stack}/{app}".ljust(width)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {label}  {detail}")
    passed = sum(1 for *_, ok, _ in _ROWS for ok in [ok])
    print(f"=== {passed}/{len(_ROWS)} apps booted and crawled successfully ===\n")


@pytest.mark.skipif(
    not live_boot_available(),
    reason="php_laravel live-boot requires composer + php on PATH and Packagist reachability (PA-0005)",
)
@pytest.mark.parametrize("app_key", ["circlefeed", "huddlehub", "booking"])
def test_php_laravel_app_boots_and_is_crawlable(app_key, php_crawls) -> None:
    crawl = php_crawls(app_key)
    spec = _PHP_SPECS[app_key]
    home_status = crawl.pages.get("/", (None, None))[0]
    ok = home_status == 200 and crawl.total_rows >= spec.min_discovered_pages
    _record("php_laravel", app_key, ok, f"home={home_status} rows={crawl.total_rows}")
    assert home_status == 200, crawl.pages
    assert crawl.total_rows >= spec.min_discovered_pages, (app_key, crawl.total_rows)


@pytest.mark.skipif(
    not django_boot_available(),
    reason="django live-boot requires python3/venv and a real PyPI reachability probe (PA-0005/PA-0035)",
)
def test_django_pictrail_boots_and_is_crawlable(django_crawl) -> None:
    home_status = django_crawl["pages"].get("/", (None, None))[0]
    rows = len(django_crawl["rows"])
    ok = home_status == 200 and rows >= _DJANGO_MIN_PAGES
    _record("django", "pictrail", ok, f"home={home_status} rows={rows}")
    assert home_status == 200, django_crawl["pages"]
    assert rows >= _DJANGO_MIN_PAGES, rows


@pytest.mark.skipif(
    not go_boot_available(),
    reason="go_net_http live-boot requires the go toolchain and a module-proxy round trip (PA-0005/PA-0035)",
)
def test_go_net_http_loopcast_boots_and_is_crawlable(go_crawl) -> None:
    home_status = go_crawl["pages"].get("/", (None, None))[0]
    rows = len(go_crawl["rows"])
    ok = home_status == 200 and rows >= _GO_MIN_PAGES
    _record("go_net_http", "loopcast", ok, f"home={home_status} rows={rows}")
    assert home_status == 200, go_crawl["pages"]
    assert rows >= _GO_MIN_PAGES, rows


@pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason="spring_boot live-boot requires java + mvn on PATH and Maven Central reachability (PA-0005)",
)
def test_spring_boot_app_boots_and_is_crawlable(spring_crawl) -> None:
    app_key = spring_crawl["app_key"]
    config = _SPRING_APPS[app_key]
    home_status = spring_crawl["pages"].get("/", (None, None))[0]
    rows = len(spring_crawl["rows"])
    ok = home_status == 200 and rows >= config["min_discovered_pages"]
    _record("spring_boot", app_key, ok, f"home={home_status} rows={rows}")
    assert home_status == 200, spring_crawl["pages"]
    assert rows >= config["min_discovered_pages"], (app_key, rows)


@pytest.mark.skipif(
    not rails_boot_available(),
    reason="ruby_rails live-boot requires ruby/bundler on PATH and rubygems.org reachability (PA-0005/PA-0035)",
)
def test_ruby_rails_forgecart_boots_and_is_crawlable(rails_site) -> None:
    home_status = rails_site["pages"].get("/", (None, None))[0]
    rows = len(rails_site["rows"])
    ok = home_status == 200 and rows >= _RAILS_MIN_PAGES
    _record("ruby_rails", "forgecart", ok, f"home={home_status} rows={rows}")
    assert home_status == 200, rails_site["pages"]
    assert rows >= _RAILS_MIN_PAGES, rows


def _node_express_available() -> bool:
    from ._meadowmart_app import node_available, npm_registry_reachable
    from pathlib import Path
    import tempfile

    if not node_available():
        return False
    with tempfile.TemporaryDirectory(prefix="fuzzlab-node-probe-") as scratch:
        return npm_registry_reachable(Path(scratch))


@pytest.mark.skipif(
    not _node_express_available(),
    reason="node_express live-boot requires node/npm on PATH and a real npm-registry probe (PA-0005/PA-0035)",
)
def test_node_express_meadowmart_boots_and_is_crawlable(node_crawl) -> None:
    home_status = node_crawl["by_path"].get("/", [(None, None, None)])[0][0]
    rows = len(node_crawl["rows"])
    ok = home_status == 200 and rows >= _NODE_MIN_PAGES
    _record("node_express", "meadowmart", ok, f"home={home_status} rows={rows}")
    assert home_status == 200, node_crawl["by_path"]
    assert rows >= _NODE_MIN_PAGES, rows
