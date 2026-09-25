"""CC-LAB-0247 (Lane 7, §2a/Gate B): offline dual-path proof for the three
new per-stack `assemble_<stack>_app(dest)` functions (`django`, `go_net_http`,
`ruby_rails`) -- lifted from each stack's own live-boot harness's private
`_assemble()`, the same move Lane 4 made public for `spring_boot`.

Each new function is proved live-bootable **without a second real boot**:
its output tree is asserted byte-identical, file by file, to what the
harness's own already-proven `_assemble()` writes for the exact same cell
set. Since each stack's own existing navigability live-boot suite already
boots that same whole-app cell set (`app_cells()`) through the harness and
passes, byte-identity here transitively proves the new function's output is
just as live-bootable -- never assumed from a passing template compile
alone (S1/S8, plan §3).

Offline only, no real venv/pip/go/bundler process -- `_assemble()` itself
does no boot, it only writes files, so this needs no live-boot skip guard.
"""

from __future__ import annotations

import filecmp
import os

import pytest


def _assert_trees_identical(dir_a: str, dir_b: str) -> None:
    """Recursively assert every file under `dir_a` exists, byte-identical,
    under `dir_b`, and vice versa -- a stronger check than `filecmp.dircmp`
    alone, which by default does not recurse into common subdirectories."""
    cmp = filecmp.dircmp(dir_a, dir_b)
    assert not cmp.left_only, (dir_a, "has files/dirs not in", dir_b, cmp.left_only)
    assert not cmp.right_only, (dir_b, "has files/dirs not in", dir_a, cmp.right_only)
    _, mismatch, errors = filecmp.cmpfiles(dir_a, dir_b, cmp.common_files, shallow=False)
    assert not mismatch, (dir_a, dir_b, "byte-differ on", mismatch)
    assert not errors, (dir_a, dir_b, "could not compare", errors)
    for sub in cmp.common_dirs:
        _assert_trees_identical(os.path.join(dir_a, sub), os.path.join(dir_b, sub))


def test_assemble_django_app_matches_harness_assemble(tmp_path) -> None:
    from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness
    from fuzzlab.labgen.emitters.django import DjangoEmitter, app_cells, assemble_django_app

    cells = app_cells()
    assert cells, "app_cells() must be non-vacuous"

    via_function = tmp_path / "via_function"
    assemble_django_app(str(via_function))

    harness = DjangoLiveBootHarness(DjangoEmitter(), cells)
    harness._app_dir = tmp_path / "via_harness"
    harness._assemble()

    _assert_trees_identical(str(via_function), str(harness._app_dir))


def test_assemble_go_net_http_app_matches_harness_assemble(tmp_path) -> None:
    from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness
    from fuzzlab.labgen.emitters.go_net_http import GoEmitter, app_cells, assemble_go_net_http_app

    cells = app_cells()
    assert cells, "app_cells() must be non-vacuous"

    via_function = tmp_path / "via_function"
    assemble_go_net_http_app(str(via_function))

    harness = GoLiveBootHarness(GoEmitter(), cells)
    harness._app_dir = tmp_path / "via_harness"
    harness._assemble()

    _assert_trees_identical(str(via_function), str(harness._app_dir))


def test_assemble_ruby_rails_app_matches_harness_assemble(tmp_path) -> None:
    from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness
    from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter, app_cells, assemble_ruby_rails_app

    cells = app_cells()
    assert cells, "app_cells() must be non-vacuous"

    via_function = tmp_path / "via_function"
    assemble_ruby_rails_app(str(via_function))

    harness = RailsLiveBootHarness(RailsEmitter(), cells)
    harness._app_dir = tmp_path / "via_harness"
    harness._assemble()

    _assert_trees_identical(str(via_function), str(harness._app_dir))


def test_app_cells_functions_partition_stable_and_non_vacuous() -> None:
    """S8: each new `app_cells()` reuses the exact predicate
    (`stack_profile` + `emitter.supports()`) each stack's own existing
    navigability test's private cell-loading helper already uses -- never a
    second, hand-written copy. Regression pin: non-vacuous and stable
    across two calls (deterministic manifest scan, PA-0027)."""
    from fuzzlab.labgen.emitters.django import app_cells as django_app_cells
    from fuzzlab.labgen.emitters.go_net_http import app_cells as go_app_cells
    from fuzzlab.labgen.emitters.ruby_rails import app_cells as rails_app_cells

    for fn in (django_app_cells, go_app_cells, rails_app_cells):
        first = [c.cell_id for c in fn()]
        second = [c.cell_id for c in fn()]
        assert first, fn
        assert first == second, fn
