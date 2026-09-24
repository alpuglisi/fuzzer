"""Tests for `fuzzlab.labgen.assemble`'s `--app` split (Lane 1 step 2,
`docs/LAB_BROWSABLE_APPS_PLAN.md`, `CC-LAB-0238`/`FR-LAB-156`).

Confirms: (1) the default (no `app`) build is unaffected -- still every
cell, including CircleFeed/Huddle Hub/Booking's, and still Puppy Fort
Factory's own static site layer; (2) `app="circlefeed"` (and its siblings)
keeps only that app's own cells and overwrites the site layer with that
app's branding; (3) an unknown `app` value is rejected rather than silently
building the default set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fuzzlab.labgen.assemble import assemble_lab, collect_cells
from fuzzlab.labgen.emitters.php_laravel.app_site import APP_REGISTRY


def test_default_build_includes_every_apps_cells() -> None:
    cells = collect_cells()
    cell_ids = {cell.cell_id for cell in cells}
    assert any(cell_id.startswith("LABGEN-CF-") for cell_id in cell_ids)
    assert any(cell_id.startswith("LABGEN-HHB-") for cell_id in cell_ids)
    assert any(cell_id.startswith("LABGEN-BC-") for cell_id in cell_ids)
    assert any(cell_id.startswith("LABGEN-PL-") for cell_id in cell_ids)


@pytest.mark.parametrize("app_key", sorted(APP_REGISTRY))
def test_app_split_keeps_only_that_apps_cells(app_key: str) -> None:
    prefix = APP_REGISTRY[app_key]["prefix"]
    cells = collect_cells(cell_id_prefix=prefix)
    assert cells, f"{app_key} should have at least one cell"
    assert all(cell.cell_id.startswith(prefix) for cell in cells)

    other_prefixes = [meta["prefix"] for key, meta in APP_REGISTRY.items() if key != app_key]
    for other_prefix in other_prefixes:
        assert not any(cell.cell_id.startswith(other_prefix) for cell in cells)


def test_assemble_lab_app_split_writes_branded_site_layer(tmp_path: Path) -> None:
    out_dir = tmp_path / "circlefeed"
    cells = assemble_lab(out_dir, app="circlefeed")

    assert cells, "expected at least one CircleFeed cell"
    assert all(cell.cell_id.startswith("LABGEN-CF-") for cell in cells)

    home = (out_dir / "resources" / "views" / "site" / "home.blade.php").read_text()
    assert "CircleFeed" in home

    layout = (out_dir / "resources" / "views" / "layouts" / "site.blade.php").read_text()
    assert "CircleFeed" in layout

    site_routes = (out_dir / "routes" / "site.php").read_text()
    assert "loginForm" not in site_routes
    assert "'home'" in site_routes
    assert "'catalog'" in site_routes

    # The per-cell route fragments are unaffected -- still only this app's cells.
    web_routes = (out_dir / "routes" / "web.php").read_text()
    assert "LABGEN-CF-" in web_routes
    assert "LABGEN-HHB-" not in web_routes
    assert "LABGEN-BC-" not in web_routes


def test_assemble_lab_default_keeps_pff_site_layer(tmp_path: Path) -> None:
    out_dir = tmp_path / "pff"
    assemble_lab(out_dir)

    home = (out_dir / "resources" / "views" / "site" / "home.blade.php").read_text()
    assert "Puppy Fort Factory" in home

    web_routes = (out_dir / "routes" / "web.php").read_text()
    assert "LABGEN-CF-" in web_routes
    assert "LABGEN-HHB-" in web_routes
    assert "LABGEN-BC-" in web_routes


def test_assemble_lab_rejects_unknown_app(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown app"):
        assemble_lab(tmp_path / "nope", app="not-a-real-app")
