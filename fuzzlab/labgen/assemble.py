"""Assemble the full generated ``php_laravel`` lab -- the atomic cutover's
(``L-P3.3c-CUT``, ``CC-LAB-0061``/``FR-LAB-58``) single source of the PHP
target lab, replacing the hand-built ``puppy-fort-factory/`` directory this
lane retires.

Generalizes :class:`fuzzlab.labgen.conformance.live_boot.LiveBootHarness.
_assemble` (which assembles exactly one manifest's cells for an ephemeral
test boot) to **every** ``lab/manifests/*.yaml`` cell the ``php_laravel``
emitter supports, deduplicated by cell id -- the same manifest-discovery and
``supports()``-gated walk :mod:`fuzzlab.labgen.cutover_gate`'s
``compute_php_laravel_coverage`` already uses (PA-0001/PA-0027: one derived
walk, not two independently-maintained ones), so the set of cells this
module writes out is always exactly the set the cutover gate already proved
covers every non-exempted ``PFF-`` case.

Two callers, one function:

* ``lab/web.Dockerfile`` runs this at image-build time (``python3 -m
  fuzzlab.labgen.assemble --out /var/www/html``) so the served app is a
  build artifact of the generator, never a hand-edited checked-in tree.
* ``deploy.sh`` runs the same entry point for a bare-metal (non-Docker) LAMP
  deployment, per ``docs/ON_HOST_RUNBOOK.md``'s manual alternative.
"""

from __future__ import annotations

import argparse
import glob as _glob
import shutil
import sys
from pathlib import Path

from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labgen.schema import Cell, load_manifest

__all__ = ["DEFAULT_MANIFESTS_GLOB", "SKELETON_DIR", "collect_cells", "assemble_lab", "main"]

#: Mirrors ``fuzzlab.labgen.cutover_gate.DEFAULT_MANIFESTS_GLOB`` exactly --
#: the one place both the coverage gate and the real assembly derive "every
#: manifest" from, so they can never silently diverge on which files count.
DEFAULT_MANIFESTS_GLOB = "lab/manifests/*.yaml"

#: The checked-in Laravel 13 project skeleton, same one
#: ``fuzzlab.labgen.conformance.live_boot`` boots for its own proof --
#: reused here rather than a second copy, per PA-0003/PA-0021.
SKELETON_DIR = Path(__file__).resolve().parent / "emitters" / "php_laravel" / "stack" / "skeleton"

#: The single, shared WAF ruleset (`L-P3.3c-CUT`: re-homed from the retired
#: `puppy-fort-factory/config/waf-rules.json`) -- copied verbatim into the
#: assembled app tree so the ``FzlWaf`` middleware never needs a sibling
#: ``lab/`` checkout at runtime (a deployed/containerized app is not
#: guaranteed one). Read from the repo-relative path, matching
#: ``fuzzlab.mutation.filtermodel``'s own source of truth (PA-0003/PA-0021:
#: one shared file, two readers -- the offline `FilterModel` and this copy
#: step -- never two independently-maintained rulesets).
WAF_RULES_SRC = Path(__file__).resolve().parents[2] / "lab" / "waf-rules.json"
#: Where the copy lands inside the assembled app tree; ``FzlWaf``'s default
#: ``PFF_WAF_RULES`` path (``storage_path('app/waf-rules.json')``) matches.
WAF_RULES_DEST = Path("storage") / "app" / "waf-rules.json"


def collect_cells(
    manifest_paths: list[str] | None = None,
    *,
    emitter: Emitter | None = None,
) -> list[Cell]:
    """Every ``php_laravel``-supported cell across every manifest,
    deduplicated by ``cell_id`` (first occurrence wins), in manifest-then-
    cell order -- the deterministic input :func:`assemble_lab` renders from.
    """
    emitter = emitter if emitter is not None else LaravelEmitter()
    if manifest_paths is None:
        manifest_paths = sorted(_glob.glob(DEFAULT_MANIFESTS_GLOB))
    seen: dict[str, Cell] = {}
    for manifest_path in manifest_paths:
        manifest = load_manifest(manifest_path)
        for cell in manifest.cells:
            if cell.stack_profile != "php_laravel":
                continue
            if not emitter.supports(cell.vuln_class, cell.sink_context):
                continue
            seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


def assemble_lab(
    out_dir: Path,
    *,
    manifest_paths: list[str] | None = None,
    emitter: Emitter | None = None,
) -> list[Cell]:
    """Write the full generated lab app to ``out_dir``: the skeleton, every
    supported cell's rendered files, the accumulated ``routes/web.php``, and
    the per-build scaffold (``.env``, ``public/index.php``). Returns the
    cells rendered, so a caller (e.g. a build-time sanity check) can report
    what it built.

    ``out_dir`` is not cleared first -- the skeleton copy uses
    ``dirs_exist_ok=True`` so this is safe to re-run into a fresh empty
    directory (the normal Docker-build case) or, deliberately, on top of an
    existing checkout for local iteration; a caller wanting a clean rebuild
    removes ``out_dir`` itself first.
    """
    emitter = emitter if emitter is not None else LaravelEmitter()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SKELETON_DIR, out_dir, dirs_exist_ok=True)

    cells = collect_cells(manifest_paths, emitter=emitter)
    fragments: dict[str, str] = {}
    for cell in cells:
        for emitted in emitter.render(cell):
            dest = out_dir / emitted.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(emitted.content)
        fragments[cell.cell_id] = emitter.route_fragment_for(cell)

    from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator

    routes_file = out_dir / "routes" / "web.php"
    routes_file.write_text(RouteAccumulator().render_file(fragments), encoding="utf-8")

    for scaffold_file in emitter.render_scaffold():
        dest = out_dir / scaffold_file.path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(scaffold_file.content)

    if WAF_RULES_SRC.is_file():
        waf_dest = out_dir / WAF_RULES_DEST
        waf_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(WAF_RULES_SRC, waf_dest)

    return cells


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzlab.labgen.assemble",
        description="Assemble the full generated php_laravel lab into --out.",
    )
    parser.add_argument("--out", required=True, help="destination directory (e.g. /var/www/html)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    cells = assemble_lab(Path(args.out))
    print(f"assembled {len(cells)} php_laravel cell(s) into {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
